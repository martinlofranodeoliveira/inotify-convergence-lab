#include "icl.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WATCH_CAP (ICL_MAX_DIRS + 1u)
#define COOKIE_CAP 256u
#define WATCH_MASK (IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | \
                    IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | \
                    IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW)

struct icl {
    int parentfd, rootfd, quarantinefd, notifyfd;
    char parent[64];
    bool active, reset;
    uint64_t epoch;
    icl_state state;
    icl_error error;
    icl_evidence evidence;
    icl_limits limits;
    icl_snapshot verified;
    int watches[WATCH_CAP];
    size_t watch_count;
};

typedef struct {
    icl_snapshot map;
    char dirs[ICL_MAX_DIRS][ICL_PATH_CAP];
    size_t root_dirs;
    uint64_t entries, directories, bytes;
} inventory;

typedef struct {
    unsigned work;
    struct timespec deadline;
} budget;

typedef struct {
    uint32_t cookie;
    unsigned from, to;
    uint64_t generation;
} move_pair;

static icl_result fail(icl *l, icl_result r, int e, const char *op)
{
    l->error.result = r;
    l->error.native_errno = e;
    (void)snprintf(l->error.operation, sizeof l->error.operation, "%s", op);
    l->state = r == ICL_INCOMPLETE ? ICL_STATE_INCOMPLETE : ICL_STATE_DIRTY;
    l->reset = true;
    return r;
}

static void clear_error(icl *l)
{
    memset(&l->error, 0, sizeof l->error);
}

static bool add64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (b > UINT64_MAX - a) return false;
    *out = a + b;
    return true;
}

static icl_result increment(icl *l, uint64_t *v, const char *op)
{
    if (!add64(*v, 1, v)) return fail(l, ICL_INCOMPLETE, 0, op);
    return ICL_OK;
}

static icl_result close_keep(icl *l, int fd, icl_result r)
{
    if (close(fd) == -1 && r == ICL_OK)
        return fail(l, ICL_NATIVE, errno, "close");
    return r;
}

static icl_result budget_start(icl *l, budget *b)
{
    b->work = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &b->deadline) == -1)
        return fail(l, ICL_NATIVE, errno, "clock");
    b->deadline.tv_sec += (time_t)(l->limits.deadline_ms / 1000u);
    b->deadline.tv_nsec += (long)(l->limits.deadline_ms % 1000u) * 1000000L;
    if (b->deadline.tv_nsec >= 1000000000L) {
        b->deadline.tv_sec++;
        b->deadline.tv_nsec -= 1000000000L;
    }
    return ICL_OK;
}

static icl_result tick(icl *l, budget *b)
{
    struct timespec now;
    if (b->work >= l->limits.work_limit)
        return fail(l, ICL_INCOMPLETE, 0, "work-limit");
    b->work++;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
        return fail(l, ICL_NATIVE, errno, "clock");
    if (now.tv_sec > b->deadline.tv_sec ||
        (now.tv_sec == b->deadline.tv_sec && now.tv_nsec >= b->deadline.tv_nsec))
        return fail(l, ICL_INCOMPLETE, 0, "deadline");
    return ICL_OK;
}

static bool valid_path(const char *p)
{
    size_t component = 0, total = 0;
    unsigned depth = 1;
    if (!p || !*p) return false;
    for (; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (++total >= ICL_PATH_CAP) return false;
        if (c == '/') {
            if (!component || ++depth > ICL_MAX_DEPTH) return false;
            component = 0;
            continue;
        }
        bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9');
        if ((!component && !alnum) ||
            (!alnum && c != '.' && c != '_' && c != '-') || ++component > 32u)
            return false;
    }
    return component != 0;
}

static icl_result authorized(icl *l, uint64_t token)
{
    if (!l->active || token != l->epoch)
        return fail(l, ICL_INVALID, 0, "writer-token");
    return ICL_OK;
}

static icl_result parent_open(icl *l, const char *path, int *out,
                              char leaf[33])
{
    char copy[ICL_PATH_CAP];
    if (!valid_path(path)) return fail(l, ICL_INVALID, 0, "path-subset");
    memcpy(copy, path, strlen(path) + 1u);
    int fd = fcntl(l->rootfd, F_DUPFD_CLOEXEC, 3);
    if (fd == -1) return fail(l, ICL_NATIVE, errno, "duplicate-directory");
    char *part = copy;
    for (;;) {
        char *slash = strchr(part, '/');
        if (!slash) {
            memcpy(leaf, part, strlen(part) + 1u);
            *out = fd;
            return ICL_OK;
        }
        *slash = '\0';
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next == -1) {
            icl_result r = fail(l, ICL_NATIVE, errno, "open-parent");
            return close_keep(l, fd, r);
        }
        icl_result r = close_keep(l, fd, ICL_OK);
        if (r != ICL_OK) return close_keep(l, next, r);
        fd = next;
        part = slash + 1;
    }
}

static bool same_object(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_nlink == b->st_nlink;
}

static icl_result hash_file(icl *l, int dirfd, const char *name,
                            const struct stat *before, icl_file *file, budget *b)
{
    if (!S_ISREG(before->st_mode) || before->st_nlink != 1 ||
        before->st_size < 0 || (uint64_t)before->st_size > ICL_MAX_FILE_BYTES)
        return fail(l, ICL_INVALID, 0, "file-contract");
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd == -1) return fail(l, ICL_NATIVE, errno, "open-file");
    struct stat opened, after;
    icl_result r = ICL_OK;
    EVP_MD_CTX *ctx = NULL;
    uint64_t length = 0;
    unsigned char bytes[1024];
    if (fstat(fd, &opened) == -1) {
        r = fail(l, ICL_NATIVE, errno, "fstat-file");
        goto done;
    }
    if (!same_object(before, &opened) || !S_ISREG(opened.st_mode) || opened.st_nlink != 1) {
        r = fail(l, ICL_INVALID, 0, "changed-file");
        goto done;
    }
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        r = fail(l, ICL_NATIVE, 0, "evp-init");
        goto done;
    }
    for (;;) {
        r = tick(l, b);
        if (r != ICL_OK) goto done;
        ssize_t n = read(fd, bytes, sizeof bytes);
        if (n == -1) {
            if (errno == EINTR) continue;
            r = fail(l, ICL_NATIVE, errno, "read-file");
            goto done;
        }
        if (n == 0) break;
        if (!add64(length, (uint64_t)n, &length) || length > ICL_MAX_FILE_BYTES) {
            r = fail(l, ICL_INCOMPLETE, 0, "growing-file");
            goto done;
        }
        if (EVP_DigestUpdate(ctx, bytes, (size_t)n) != 1) {
            r = fail(l, ICL_NATIVE, 0, "evp-update");
            goto done;
        }
    }
    if (fstat(fd, &after) == -1) {
        r = fail(l, ICL_NATIVE, errno, "fstat-after-read");
        goto done;
    }
    if (!same_object(&opened, &after) || opened.st_size != after.st_size ||
        after.st_size < 0 || length != (uint64_t)after.st_size ||
        opened.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        opened.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        opened.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        opened.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        r = fail(l, ICL_INCOMPLETE, 0, "file-changed-during-read");
        goto done;
    }
    unsigned digest_length = 0;
    if (EVP_DigestFinal_ex(ctx, file->sha256, &digest_length) != 1 || digest_length != 32u) {
        r = fail(l, ICL_NATIVE, 0, "evp-final");
        goto done;
    }
    file->size = length;
done:
    EVP_MD_CTX_free(ctx);
    return close_keep(l, fd, r);
}

static icl_result add_watch(icl *l, const char *relative)
{
    if (l->watch_count >= WATCH_CAP)
        return fail(l, ICL_INCOMPLETE, 0, "watch-limit");
    char path[256];
    int n = snprintf(path, sizeof path, "%s/root%s%s", l->parent,
                     *relative ? "/" : "", relative);
    if (n < 0 || (size_t)n >= sizeof path)
        return fail(l, ICL_INCOMPLETE, 0, "watch-path-limit");
    int wd = inotify_add_watch(l->notifyfd, path, WATCH_MASK);
    if (wd == -1) {
        int saved = errno;
        icl_result r = increment(l, &l->evidence.native_watch_failures, "watch-counter");
        if (r != ICL_OK) return r;
        return fail(l, ICL_NATIVE, saved, "inotify-add-watch");
    }
    for (size_t i = 0; i < l->watch_count; i++)
        if (l->watches[i] == wd)
            return fail(l, ICL_INCOMPLETE, 0, "reused-watch-descriptor");
    l->watches[l->watch_count++] = wd;
    return ICL_OK;
}

static icl_result scan_dir(icl *l, int fd, const char *prefix, unsigned depth,
                            inventory *inv, bool root_map, bool watches, budget *b)
{
    icl_result r = tick(l, b);
    if (r != ICL_OK) return r;
    if (watches) {
        r = add_watch(l, prefix);
        if (r != ICL_OK) return r;
    }
    int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate == -1) return fail(l, ICL_NATIVE, errno, "duplicate-scan");
    /* Independent directory offsets: dup() alone shares the offset. */
    int streamfd = openat(duplicate, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (streamfd == -1) {
        r = fail(l, ICL_NATIVE, errno, "open-directory-stream");
        return close_keep(l, duplicate, r);
    }
    r = close_keep(l, duplicate, ICL_OK);
    if (r != ICL_OK) return close_keep(l, streamfd, r);
    DIR *stream = fdopendir(streamfd);
    if (!stream) {
        r = fail(l, ICL_NATIVE, errno, "fdopendir");
        return close_keep(l, streamfd, r);
    }
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(stream);
        if (!de) {
            if (errno) r = fail(l, ICL_NATIVE, errno, "readdir");
            break;
        }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        r = tick(l, b);
        if (r != ICL_OK) break;
        char path[ICL_PATH_CAP];
        int n = snprintf(path, sizeof path, "%s%s%s", prefix, *prefix ? "/" : "", de->d_name);
        if (n < 0 || (size_t)n >= sizeof path || !valid_path(path) || depth >= ICL_MAX_DEPTH) {
            r = fail(l, ICL_INVALID, 0, "namespace-subset");
            break;
        }
        if (inv->entries >= ICL_MAX_ENTRIES) {
            r = fail(l, ICL_INCOMPLETE, 0, "entry-limit");
            break;
        }
        inv->entries++;
        struct stat st;
        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            r = fail(l, ICL_NATIVE, errno, "stat-entry");
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (inv->directories >= ICL_MAX_DIRS) {
                r = fail(l, ICL_INCOMPLETE, 0, "directory-limit");
                break;
            }
            inv->directories++;
            if (root_map) {
                memcpy(inv->dirs[inv->root_dirs++], path, strlen(path) + 1u);
                inv->map.directories++;
            }
            int child = openat(fd, de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child == -1) {
                r = fail(l, ICL_NATIVE, errno, "open-directory");
                break;
            }
            struct stat actual;
            if (fstat(child, &actual) == -1)
                r = fail(l, ICL_NATIVE, errno, "fstat-directory");
            else if (!same_object(&st, &actual))
                r = fail(l, ICL_INCOMPLETE, 0, "changed-directory");
            else
                r = scan_dir(l, child, path, depth + 1u, inv, root_map, watches, b);
            r = close_keep(l, child, r);
            if (r != ICL_OK) break;
        } else if (S_ISREG(st.st_mode)) {
            icl_file file;
            memset(&file, 0, sizeof file);
            memcpy(file.path, path, strlen(path) + 1u);
            r = hash_file(l, fd, de->d_name, &st, &file, b);
            if (r != ICL_OK) break;
            if (!add64(inv->bytes, file.size, &inv->bytes) || inv->bytes > ICL_MAX_TOTAL_BYTES) {
                r = fail(l, ICL_INCOMPLETE, 0, "byte-limit");
                break;
            }
            if (root_map) {
                inv->map.file[inv->map.files++] = file;
                if (!add64(inv->map.bytes, file.size, &inv->map.bytes)) {
                    r = fail(l, ICL_INCOMPLETE, 0, "map-byte-counter");
                    break;
                }
            }
        } else {
            r = fail(l, ICL_INVALID, 0, "unsupported-entry");
            break;
        }
    }
    if (closedir(stream) == -1 && r == ICL_OK)
        r = fail(l, ICL_NATIVE, errno, "closedir");
    return r;
}

static int file_compare(const void *a, const void *b)
{
    const icl_file *x = a, *y = b;
    return strcmp(x->path, y->path); /* All accepted bytes are positive ASCII. */
}

static icl_result scan_all(icl *l, inventory *inv, bool watches)
{
    memset(inv, 0, sizeof *inv);
    budget b;
    icl_result r = budget_start(l, &b);
    if (r == ICL_OK) r = scan_dir(l, l->rootfd, "", 0, inv, true, watches, &b);
    if (r == ICL_OK) r = scan_dir(l, l->quarantinefd, "", 0, inv, false, false, &b);
    if (r == ICL_OK)
        qsort(inv->map.file, (size_t)inv->map.files, sizeof inv->map.file[0], file_compare);
    return r;
}

static icl_result new_instance(icl *l)
{
    l->reset = true;
    if (l->notifyfd != -1) {
        int fd = l->notifyfd;
        l->notifyfd = -1;
        icl_result r = close_keep(l, fd, ICL_OK);
        if (r != ICL_OK) return r;
    }
    l->watch_count = 0;
    icl_result r = increment(l, &l->evidence.instance_generation, "instance-generation");
    if (r != ICL_OK) return r;
    l->notifyfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (l->notifyfd == -1) return fail(l, ICL_NATIVE, errno, "inotify-init");
    l->reset = false;
    return ICL_OK;
}

static bool known_watch(const icl *l, int wd)
{
    for (size_t i = 0; i < l->watch_count; i++)
        if (l->watches[i] == wd) return true;
    return false;
}

static icl_result drain(icl *l, bool discard, bool *saw)
{
    union { max_align_t alignment; unsigned char data[8192]; } buffer;
    move_pair pairs[COOKIE_CAP];
    size_t pair_count = 0;
    unsigned events = 0;
    budget b;
    *saw = false;
    icl_result r = budget_start(l, &b);
    if (r != ICL_OK) return r;
    if (l->notifyfd == -1) return ICL_DIRTY;
    for (;;) {
        r = tick(l, &b);
        if (r != ICL_OK) return r;
        ssize_t n = read(l->notifyfd, buffer.data, sizeof buffer.data);
        if (n == -1) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) break;
            return fail(l, ICL_NATIVE, errno, "inotify-read");
        }
        if (!n) return fail(l, ICL_INCOMPLETE, 0, "inotify-eof");
        size_t offset = 0;
        while (offset < (size_t)n) {
            if ((size_t)n - offset < sizeof(struct inotify_event))
                return fail(l, ICL_INCOMPLETE, 0, "event-header");
            struct inotify_event ev;
            memcpy(&ev, buffer.data + offset, sizeof ev);
            if (ev.len > (size_t)n - offset - sizeof ev)
                return fail(l, ICL_INCOMPLETE, 0, "event-length");
            offset += sizeof ev + ev.len;
            *saw = true;
            l->state = ICL_STATE_DIRTY;
            if (events >= l->limits.event_limit)
                return fail(l, ICL_INCOMPLETE, 0, "event-limit");
            events++;
            if (ev.mask & IN_Q_OVERFLOW) {
                r = increment(l, &l->evidence.observed_kernel_overflows, "kernel-overflow-counter");
                if (r != ICL_OK) return r;
                l->reset = true;
                continue;
            }
            if (discard) continue;
            if (!known_watch(l, ev.wd) ||
                (ev.mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT))) {
                l->reset = true;
                continue;
            }
            if (l->reset) continue;
            if (ev.mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
                if (!ev.cookie || (ev.mask & (IN_MOVED_FROM | IN_MOVED_TO)) ==
                                  (IN_MOVED_FROM | IN_MOVED_TO)) {
                    l->reset = true;
                    continue;
                }
                size_t i;
                for (i = 0; i < pair_count; i++)
                    if (pairs[i].cookie == ev.cookie) break;
                if (i == pair_count) {
                    if (pair_count == COOKIE_CAP) {
                        l->reset = true;
                        continue;
                    }
                    pairs[i] = (move_pair){ev.cookie, 0, 0, l->evidence.instance_generation};
                    pair_count++;
                }
                if (ev.mask & IN_MOVED_FROM) pairs[i].from++;
                if (ev.mask & IN_MOVED_TO) pairs[i].to++;
                if (pairs[i].from > 1u || pairs[i].to > 1u) l->reset = true;
            }
        }
    }
    for (size_t i = 0; i < pair_count; i++)
        if (pairs[i].from != 1u || pairs[i].to != 1u ||
            pairs[i].generation != l->evidence.instance_generation)
            l->reset = true;
    if (!discard && !l->reset) {
        uint64_t count;
        if (!add64(l->evidence.matched_move_pairs, (uint64_t)pair_count, &count))
            return fail(l, ICL_INCOMPLETE, 0, "move-counter");
        l->evidence.matched_move_pairs = count;
    }
    return l->state == ICL_STATE_CURRENT && !l->reset ? ICL_OK : ICL_DIRTY;
}

icl_limits icl_default_limits(void)
{
    return (icl_limits){4096, 4096, 2000};
}

icl_result icl_set_limits(icl *l, icl_limits limits)
{
    if (!l) return ICL_INVALID;
    if (l->active || !limits.event_limit || limits.event_limit > 4096u ||
        !limits.work_limit || limits.work_limit > 8192u ||
        !limits.deadline_ms || limits.deadline_ms > 5000u)
        return fail(l, ICL_INVALID, 0, "limits");
    l->limits = limits;
    return ICL_OK;
}

static void remember_errno(int *first, int e)
{
    if (!*first) *first = e;
}

static void cleanup_dir(int fd, unsigned depth, unsigned *entries, int *first)
{
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (copy == -1) { remember_errno(first, errno); return; }
    DIR *d = fdopendir(copy);
    if (!d) {
        remember_errno(first, errno);
        if (close(copy) == -1) remember_errno(first, errno);
        return;
    }
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(d);
        if (!de) { if (errno) remember_errno(first, errno); break; }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (*entries >= ICL_MAX_ENTRIES || depth >= ICL_MAX_DEPTH) {
            remember_errno(first, EOVERFLOW);
            break;
        }
        (*entries)++;
        struct stat st;
        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            remember_errno(first, errno);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(fd, de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child == -1) { remember_errno(first, errno); continue; }
            cleanup_dir(child, depth + 1u, entries, first);
            if (close(child) == -1) remember_errno(first, errno);
            if (unlinkat(fd, de->d_name, AT_REMOVEDIR) == -1) remember_errno(first, errno);
        } else if (unlinkat(fd, de->d_name, 0) == -1) remember_errno(first, errno);
    }
    if (closedir(d) == -1) remember_errno(first, errno);
}

icl_result icl_destroy(icl *l, icl_error *error)
{
    int first = 0;
    unsigned entries = 0;
    if (!l) return ICL_INVALID;
    if (l->notifyfd != -1 && close(l->notifyfd) == -1) remember_errno(&first, errno);
    if (l->rootfd != -1) {
        cleanup_dir(l->rootfd, 0, &entries, &first);
        if (close(l->rootfd) == -1) remember_errno(&first, errno);
    }
    if (l->quarantinefd != -1) {
        cleanup_dir(l->quarantinefd, 0, &entries, &first);
        if (close(l->quarantinefd) == -1) remember_errno(&first, errno);
    }
    if (l->parentfd != -1) {
        if (unlinkat(l->parentfd, "root", AT_REMOVEDIR) == -1 && errno != ENOENT)
            remember_errno(&first, errno);
        if (unlinkat(l->parentfd, "quarantine", AT_REMOVEDIR) == -1 && errno != ENOENT)
            remember_errno(&first, errno);
        if (close(l->parentfd) == -1) remember_errno(&first, errno);
    }
    if (*l->parent && rmdir(l->parent) == -1 && errno != ENOENT) remember_errno(&first, errno);
    if (error) {
        memset(error, 0, sizeof *error);
        if (first) {
            error->result = ICL_NATIVE;
            error->native_errno = first;
            (void)snprintf(error->operation, sizeof error->operation, "cleanup");
        }
    }
    free(l);
    return first ? ICL_NATIVE : ICL_OK;
}

icl_result icl_create(icl **out, icl_error *error)
{
    if (!out) return ICL_INVALID;
    *out = NULL;
    if (error) memset(error, 0, sizeof *error);
    icl *l = calloc(1, sizeof *l);
    if (!l) {
        if (error) *error = (icl_error){ICL_NATIVE, ENOMEM, "allocate"};
        return ICL_NATIVE;
    }
    l->parentfd = l->rootfd = l->quarantinefd = l->notifyfd = -1;
    l->limits = icl_default_limits();
    l->state = ICL_STATE_INVALID;
    l->reset = true;
    char template[] = "/tmp/icl-XXXXXX";
    const char *op = "mkdtemp";
    if (!mkdtemp(template)) goto failed;
    memcpy(l->parent, template, sizeof template);
    op = "open-owned-parent";
    l->parentfd = open(l->parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (l->parentfd == -1) goto failed;
    op = "mkdir-owned-root";
    if (mkdirat(l->parentfd, "root", 0700) == -1) goto failed;
    op = "mkdir-owned-quarantine";
    if (mkdirat(l->parentfd, "quarantine", 0700) == -1) goto failed;
    op = "open-owned-root";
    l->rootfd = openat(l->parentfd, "root", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (l->rootfd == -1) goto failed;
    op = "open-owned-quarantine";
    l->quarantinefd = openat(l->parentfd, "quarantine", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (l->quarantinefd == -1) goto failed;
    *out = l;
    return ICL_OK;
failed: {
        int saved = errno;
        if (error) {
            error->result = ICL_NATIVE;
            error->native_errno = saved;
            (void)snprintf(error->operation, sizeof error->operation, "%s", op);
        }
        icl_error cleanup_error;
        (void)icl_destroy(l, &cleanup_error);
        return ICL_NATIVE;
    }
}

const icl_error *icl_last_error(const icl *l) { return l ? &l->error : NULL; }
const icl_evidence *icl_get_evidence(const icl *l) { return l ? &l->evidence : NULL; }

const icl_snapshot *icl_snapshot_get(const icl *l, icl_state *state)
{
    if (!l) { if (state) *state = ICL_STATE_INVALID; return NULL; }
    if (state) *state = l->state;
    return &l->verified;
}

icl_result icl_writer_begin(icl *l, uint64_t *token)
{
    if (!l || !token) return ICL_INVALID;
    if (l->active) return fail(l, ICL_INVALID, 0, "writer-already-active");
    if (l->epoch == UINT64_MAX) return fail(l, ICL_INCOMPLETE, 0, "writer-epoch");
    clear_error(l);
    l->epoch++;
    l->state = ICL_STATE_DIRTY;
    l->active = true;
    *token = l->epoch;
    return ICL_OK;
}

icl_result icl_writer_end(icl *l, uint64_t token)
{
    if (!l) return ICL_INVALID;
    icl_result r = authorized(l, token);
    if (r != ICL_OK) return r;
    l->active = false;
    return ICL_OK;
}

icl_result icl_writer_mkdir(icl *l, uint64_t token, const char *path)
{
    if (!l) return ICL_INVALID;
    icl_result r = authorized(l, token);
    if (r != ICL_OK) return r;
    if (!valid_path(path)) return fail(l, ICL_INVALID, 0, "path-subset");
    inventory inv;
    r = scan_all(l, &inv, false);
    if (r != ICL_OK) return r;
    if (inv.entries >= ICL_MAX_ENTRIES || inv.directories >= ICL_MAX_DIRS)
        return fail(l, ICL_INCOMPLETE, 0, "mkdir-quota");
    int fd; char leaf[33];
    r = parent_open(l, path, &fd, leaf);
    if (r != ICL_OK) return r;
    if (mkdirat(fd, leaf, 0700) == -1) r = fail(l, ICL_NATIVE, errno, "mkdirat");
    return close_keep(l, fd, r);
}

icl_result icl_writer_put(icl *l, uint64_t token, const char *path,
                          const void *bytes, size_t length, int append)
{
    if (!l) return ICL_INVALID;
    icl_result r = authorized(l, token);
    if (r != ICL_OK) return r;
    if (!valid_path(path) || (length && !bytes) || length > ICL_MAX_FILE_BYTES ||
        (append != 0 && append != 1)) return fail(l, ICL_INVALID, 0, "put-arguments");
    inventory inv;
    r = scan_all(l, &inv, false);
    if (r != ICL_OK) return r;
    int dirfd; char leaf[33];
    r = parent_open(l, path, &dirfd, leaf);
    if (r != ICL_OK) return r;
    struct stat old;
    bool exists = false;
    if (fstatat(dirfd, leaf, &old, AT_SYMLINK_NOFOLLOW) == 0) exists = true;
    else if (errno != ENOENT) r = fail(l, ICL_NATIVE, errno, "stat-write-target");
    uint64_t oldsize = 0, newsize = (uint64_t)length, total = 0;
    if (r == ICL_OK && exists) {
        if (!S_ISREG(old.st_mode) || old.st_nlink != 1 || old.st_size < 0)
            r = fail(l, ICL_INVALID, 0, "write-target-type");
        else oldsize = (uint64_t)old.st_size;
    }
    if (r == ICL_OK && append && !add64(oldsize, (uint64_t)length, &newsize))
        r = fail(l, ICL_INCOMPLETE, 0, "write-size-counter");
    if (r == ICL_OK && (newsize > ICL_MAX_FILE_BYTES ||
        (!exists && inv.entries >= ICL_MAX_ENTRIES) || inv.bytes < oldsize ||
        !add64(inv.bytes - oldsize, newsize, &total) || total > ICL_MAX_TOTAL_BYTES))
        r = fail(l, ICL_INCOMPLETE, 0, "write-quota");
    if (r != ICL_OK) return close_keep(l, dirfd, r);
    int flags = O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    if (!exists) flags |= O_CREAT | O_EXCL;
    if (append) flags |= O_APPEND;
    int fd = openat(dirfd, leaf, flags, 0600);
    if (fd == -1) {
        r = fail(l, ICL_NATIVE, errno, "open-write");
        return close_keep(l, dirfd, r);
    }
    struct stat actual;
    if (fstat(fd, &actual) == -1) r = fail(l, ICL_NATIVE, errno, "fstat-write");
    else if (!S_ISREG(actual.st_mode) || actual.st_nlink != 1 ||
             (exists && !same_object(&old, &actual)))
        r = fail(l, ICL_INVALID, 0, "changed-write-target");
    if (r == ICL_OK && !append && ftruncate(fd, 0) == -1)
        r = fail(l, ICL_NATIVE, errno, "truncate-write");
    budget b;
    if (r == ICL_OK) r = budget_start(l, &b);
    size_t offset = 0;
    while (r == ICL_OK && offset < length) {
        r = tick(l, &b);
        if (r != ICL_OK) break;
        ssize_t n = write(fd, (const unsigned char *)bytes + offset, length - offset);
        if (n == -1 && errno == EINTR) continue;
        if (n <= 0) { r = fail(l, ICL_NATIVE, n == 0 ? EIO : errno, "write-file"); break; }
        offset += (size_t)n;
    }
    r = close_keep(l, fd, r);
    return close_keep(l, dirfd, r);
}

static bool below(const char *p, const char *base)
{
    size_t n = strlen(base);
    return !strncmp(p, base, n) && (p[n] == '/' || p[n] == '\0');
}

static bool renamed_path_valid(const char *p, const char *from, const char *to)
{
    if (!below(p, from)) return true;
    char result[ICL_PATH_CAP];
    int n = snprintf(result, sizeof result, "%s%s", to, p + strlen(from));
    return n >= 0 && (size_t)n < sizeof result && valid_path(result);
}

icl_result icl_writer_rename(icl *l, uint64_t token, const char *from, const char *to)
{
    if (!l) return ICL_INVALID;
    icl_result r = authorized(l, token);
    if (r != ICL_OK) return r;
    if (!valid_path(from) || !valid_path(to)) return fail(l, ICL_INVALID, 0, "path-subset");
    inventory inv;
    r = scan_all(l, &inv, false);
    if (r != ICL_OK) return r;
    for (size_t i = 0; i < inv.root_dirs; i++)
        if (!renamed_path_valid(inv.dirs[i], from, to))
            return fail(l, ICL_INVALID, 0, "rename-depth");
    for (uint64_t i = 0; i < inv.map.files; i++)
        if (!renamed_path_valid(inv.map.file[i].path, from, to))
            return fail(l, ICL_INVALID, 0, "rename-depth");
    int a, b; char x[33], y[33];
    r = parent_open(l, from, &a, x);
    if (r != ICL_OK) return r;
    r = parent_open(l, to, &b, y);
    if (r != ICL_OK) return close_keep(l, a, r);
    if (renameat(a, x, b, y) == -1) r = fail(l, ICL_NATIVE, errno, "renameat");
    r = close_keep(l, b, r);
    return close_keep(l, a, r);
}

icl_result icl_writer_quarantine(icl *l, uint64_t token, const char *path)
{
    if (!l) return ICL_INVALID;
    icl_result r = authorized(l, token);
    if (r != ICL_OK) return r;
    inventory inv;
    r = scan_all(l, &inv, false);
    if (r != ICL_OK) return r;
    int fd; char leaf[33];
    r = parent_open(l, path, &fd, leaf);
    if (r != ICL_OK) return r;
    struct stat st;
    if (fstatat(fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == -1)
        r = fail(l, ICL_NATIVE, errno, "stat-quarantine-source");
    else if (!S_ISREG(st.st_mode) || st.st_nlink != 1)
        r = fail(l, ICL_INVALID, 0, "quarantine-source-type");
    if (r == ICL_OK) {
        if (fstatat(l->quarantinefd, "exile", &st, AT_SYMLINK_NOFOLLOW) == 0)
            r = fail(l, ICL_INVALID, 0, "quarantine-occupied");
        else if (errno != ENOENT) r = fail(l, ICL_NATIVE, errno, "stat-quarantine");
    }
    if (r == ICL_OK && renameat(fd, leaf, l->quarantinefd, "exile") == -1)
        r = fail(l, ICL_NATIVE, errno, "rename-quarantine");
    return close_keep(l, fd, r);
}

icl_result icl_writer_remove(icl *l, uint64_t token, const char *path)
{
    if (!l) return ICL_INVALID;
    icl_result r = authorized(l, token);
    if (r != ICL_OK) return r;
    int fd; char leaf[33];
    r = parent_open(l, path, &fd, leaf);
    if (r != ICL_OK) return r;
    struct stat st;
    if (fstatat(fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == -1)
        r = fail(l, ICL_NATIVE, errno, "stat-remove");
    else if (unlinkat(fd, leaf, S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0) == -1)
        r = fail(l, ICL_NATIVE, errno, "unlinkat");
    return close_keep(l, fd, r);
}

icl_result icl_writer_probe(icl *l, uint64_t token, icl_probe probe)
{
    if (!l) return ICL_INVALID;
    icl_result r = authorized(l, token);
    if (r != ICL_OK) return r;
    if (probe == ICL_PROBE_READ_ERROR) {
        unsigned char byte;
        ssize_t n = read(l->rootfd, &byte, 1);
        if (n == -1) return fail(l, ICL_NATIVE, errno, "native-directory-read");
        return fail(l, ICL_INVALID, 0, "unexpected-directory-read");
    }
    inventory inv;
    r = scan_all(l, &inv, false);
    if (r != ICL_OK) return r;
    if (inv.entries >= ICL_MAX_ENTRIES)
        return fail(l, ICL_INCOMPLETE, 0, "probe-entry-quota");
    switch (probe) {
    case ICL_PROBE_SYMLINK:
        if (symlinkat("../quarantine", l->rootfd, "bad-link") == -1)
            return fail(l, ICL_NATIVE, errno, "symlink-probe");
        return ICL_OK;
    case ICL_PROBE_HARDLINK:
        if (linkat(l->rootfd, "a.txt", l->rootfd, "bad-hard", 0) == -1)
            return fail(l, ICL_NATIVE, errno, "hardlink-probe");
        return ICL_OK;
    case ICL_PROBE_FIFO:
        if (mkfifoat(l->rootfd, "bad-fifo", 0600) == -1)
            return fail(l, ICL_NATIVE, errno, "fifo-probe");
        return ICL_OK;
    case ICL_PROBE_REMOVED_WATCH: {
        if (inv.directories >= ICL_MAX_DIRS)
            return fail(l, ICL_INCOMPLETE, 0, "probe-directory-quota");
        if (mkdirat(l->rootfd, "watch-gone", 0700) == -1)
            return fail(l, ICL_NATIVE, errno, "probe-mkdir");
        if (unlinkat(l->rootfd, "watch-gone", AT_REMOVEDIR) == -1)
            return fail(l, ICL_NATIVE, errno, "probe-rmdir");
        if (l->notifyfd == -1) {
            r = new_instance(l);
            if (r != ICL_OK) return r;
        }
        r = add_watch(l, "watch-gone");
        if (r == ICL_OK) return fail(l, ICL_INVALID, 0, "unexpected-watch-success");
        return r;
    }
    default:
        return fail(l, ICL_INVALID, 0, "probe-kind");
    }
}

icl_result icl_consume_events(icl *l)
{
    if (!l) return ICL_INVALID;
    bool saw;
    return drain(l, false, &saw);
}

icl_result icl_discard_events(icl *l)
{
    if (!l) return ICL_INVALID;
    l->state = ICL_STATE_DIRTY;
    l->reset = true;
    icl_result r = increment(l, &l->evidence.discarded_drains, "discard-counter");
    if (r != ICL_OK) return r;
    bool saw;
    return drain(l, true, &saw);
}

icl_result icl_simulate_overflow(icl *l)
{
    if (!l) return ICL_INVALID;
    l->state = ICL_STATE_DIRTY;
    l->reset = true;
    return increment(l, &l->evidence.simulated_overflows, "simulated-overflow-counter");
}

icl_result icl_reconcile(icl *l)
{
    if (!l) return ICL_INVALID;
    if (l->active) return fail(l, ICL_INVALID, 0, "writer-not-quiescent");
    clear_error(l);
    bool saw;
    icl_result r;
    if (l->notifyfd != -1 && !l->reset) {
        r = drain(l, false, &saw);
        if (r != ICL_OK && r != ICL_DIRTY) goto incomplete;
    }
    /* Always rebuild. Old cookies and watch IDs never enter the new instance. */
    r = new_instance(l);
    if (r != ICL_OK) goto incomplete;
    inventory inv;
    r = scan_all(l, &inv, true);
    if (r != ICL_OK) goto incomplete;
    r = drain(l, false, &saw);
    if (r != ICL_OK && r != ICL_DIRTY) goto incomplete;
    if (saw || l->reset) {
        r = fail(l, ICL_INCOMPLETE, 0, "events-during-reconcile");
        goto incomplete;
    }
    if (!add64(l->verified.generation, 1, &inv.map.generation)) {
        r = fail(l, ICL_INCOMPLETE, 0, "snapshot-generation");
        goto incomplete;
    }
    inv.map.writer_epoch = l->epoch;
    l->verified = inv.map;
    l->state = ICL_STATE_CURRENT;
    clear_error(l);
    return ICL_OK;
incomplete:
    l->state = ICL_STATE_INCOMPLETE;
    l->reset = true;
    return r;
}

icl_result icl_oracle_root_fd(icl *l, int *out)
{
    if (!l || !out) return ICL_INVALID;
    *out = fcntl(l->rootfd, F_DUPFD_CLOEXEC, 3);
    if (*out == -1) return fail(l, ICL_NATIVE, errno, "oracle-duplicate");
    return ICL_OK;
}
