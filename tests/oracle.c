#include "oracle.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Independent test implementation: whole-file one-shot EVP, no library scanner. */
static int enumerate(int fd, const char *prefix, unsigned depth, icl_snapshot *map)
{
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (copy < 0) return -1;
    DIR *d = fdopendir(copy);
    if (!d) { int c = close(copy); (void)c; return -1; }
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(d);
        if (!de) { if (errno) result = -1; break; }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        size_t a = strlen(prefix), b = strlen(de->d_name);
        if (depth >= ICL_MAX_DEPTH || a + b + (a != 0) >= ICL_PATH_CAP) { result = -1; break; }
        char path[ICL_PATH_CAP];
        memcpy(path, prefix, a);
        size_t at = a;
        if (a) path[at++] = '/';
        memcpy(path + at, de->d_name, b + 1u);
        struct stat st;
        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW)) { result = -1; break; }
        if (S_ISDIR(st.st_mode)) {
            if (++map->directories > ICL_MAX_DIRS) { result = -1; break; }
            int child = openat(fd, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) { result = -1; break; }
            int r = enumerate(child, path, depth + 1u, map);
            if (close(child)) r = -1;
            if (r) { result = -1; break; }
        } else {
            if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || map->files >= ICL_MAX_ENTRIES) {
                result = -1; break;
            }
            int filefd = openat(fd, de->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            if (filefd < 0) { result = -1; break; }
            unsigned char data[ICL_MAX_FILE_BYTES + 1u];
            size_t used = 0;
            int bad = 0;
            while (used < sizeof data) {
                ssize_t n = read(filefd, data + used, sizeof data - used);
                if (n < 0 && errno == EINTR) continue;
                if (n < 0) { bad = 1; break; }
                if (!n) break;
                used += (size_t)n;
            }
            if (close(filefd)) bad = 1;
            if (bad || used > ICL_MAX_FILE_BYTES || st.st_size < 0 || used != (uint64_t)st.st_size) {
                result = -1; break;
            }
            icl_file *f = &map->file[map->files];
            memcpy(f->path, path, strlen(path) + 1u);
            f->size = used;
            size_t digest_size = 0;
            if (EVP_Q_digest(NULL, "SHA256", NULL, data, used, f->sha256, &digest_size) != 1 ||
                digest_size != 32u) { result = -1; break; }
            map->files++;
            map->bytes += used;
            if (map->bytes > ICL_MAX_TOTAL_BYTES) { result = -1; break; }
        }
    }
    if (closedir(d)) result = -1;
    return result;
}

static int order(const void *a, const void *b)
{
    const icl_file *x = a, *y = b;
    return strcmp(x->path, y->path);
}

int oracle_check(icl *lab)
{
    icl_state state;
    const icl_snapshot *actual = icl_snapshot_get(lab, &state);
    if (!actual || state != ICL_STATE_CURRENT) return -1;
    icl_snapshot expected;
    memset(&expected, 0, sizeof expected);
    int fd;
    if (icl_oracle_root_fd(lab, &fd) != ICL_OK) return -1;
    int r = enumerate(fd, "", 0, &expected);
    if (close(fd)) r = -1;
    if (r) return -1;
    qsort(expected.file, (size_t)expected.files, sizeof expected.file[0], order);
    if (actual->files != expected.files || actual->directories != expected.directories ||
        actual->bytes != expected.bytes) return -1;
    for (uint64_t i = 0; i < actual->files; i++)
        if (strcmp(actual->file[i].path, expected.file[i].path) ||
            actual->file[i].size != expected.file[i].size ||
            memcmp(actual->file[i].sha256, expected.file[i].sha256, 32)) return -1;
    return 0;
}

int oracle_content(icl *lab, const char *path, const void *expected, size_t length)
{
    if (strlen(path) >= ICL_PATH_CAP || length > ICL_MAX_FILE_BYTES) return -1;
    char copy[ICL_PATH_CAP];
    memcpy(copy, path, strlen(path) + 1u);
    int fd;
    if (icl_oracle_root_fd(lab, &fd) != ICL_OK) return -1;
    char *part = copy;
    for (;;) {
        char *slash = strchr(part, '/');
        if (!slash) break;
        *slash = 0;
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int bad = close(fd);
        if (next < 0) return -1;
        if (bad) { int c = close(next); (void)c; return -1; }
        fd = next;
        part = slash + 1;
    }
    int filefd = openat(fd, part, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int bad = close(fd);
    if (filefd < 0) return -1;
    unsigned char data[ICL_MAX_FILE_BYTES + 1u];
    size_t used = 0;
    while (!bad && used < sizeof data) {
        ssize_t n = read(filefd, data + used, sizeof data - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { bad = 1; break; }
        if (!n) break;
        used += (size_t)n;
    }
    if (close(filefd)) bad = 1;
    return !bad && used == length && !memcmp(data, expected, length) ? 0 : -1;
}
