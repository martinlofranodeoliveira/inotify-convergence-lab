#include "icl.h"
#include "oracle.h"
#include "scenario.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "test failed at line %d\n", __LINE__); goto failed; \
} } while (0)
#define OK(x) CHECK((x) == ICL_OK)

static int protocols_and_failures(void)
{
    icl *l = NULL;
    icl_error e;
    uint64_t a, b;
    icl_state state;
    OK(icl_create(&l, &e));
    CHECK(icl_snapshot_get(l, &state)->generation == 0 && state == ICL_STATE_INVALID);
    OK(icl_reconcile(l));
    CHECK(!oracle_check(l));
    icl_snapshot saved = *icl_snapshot_get(l, NULL);
    OK(icl_writer_begin(l, &a));
    CHECK(icl_snapshot_get(l, &state)->generation == saved.generation && state == ICL_STATE_DIRTY);
    CHECK(!memcmp(&saved, icl_snapshot_get(l, NULL), sizeof saved));
    CHECK(icl_reconcile(l) == ICL_INVALID);
    OK(icl_writer_end(l, a));
    OK(icl_writer_begin(l, &b));
    CHECK(b > a);
    CHECK(icl_writer_end(l, a) == ICL_INVALID);
    CHECK(icl_writer_put(l, a, "wrong", "x", 1, 0) == ICL_INVALID);
    CHECK(icl_writer_put(l, b, "missing/file", "x", 1, 0) == ICL_NATIVE);
    CHECK(icl_last_error(l)->native_errno == ENOENT);
    CHECK(icl_writer_rename(l, b, "absent", "other") == ICL_NATIVE);
    CHECK(icl_last_error(l)->native_errno == ENOENT);
    CHECK(icl_writer_probe(l, b, ICL_PROBE_READ_ERROR) == ICL_NATIVE);
    CHECK(icl_last_error(l)->native_errno == EISDIR);
    OK(icl_writer_put(l, b, "a.txt", "ab", 2, 0));
    OK(icl_writer_put(l, b, "Z.txt", "Z", 1, 0));
    OK(icl_writer_end(l, b));
    OK(icl_reconcile(l));
    CHECK(!oracle_check(l));
    CHECK(!strcmp(icl_snapshot_get(l, NULL)->file[0].path, "Z.txt"));
    saved = *icl_snapshot_get(l, NULL);
    OK(icl_writer_begin(l, &a));
    OK(icl_writer_put(l, a, "a.txt", "new", 3, 0));
    OK(icl_writer_end(l, a));
    icl_limits low = icl_default_limits();
    low.work_limit = 1;
    OK(icl_set_limits(l, low));
    CHECK(icl_reconcile(l) == ICL_INCOMPLETE);
    CHECK(icl_snapshot_get(l, &state)->generation == saved.generation && state == ICL_STATE_INCOMPLETE);
    CHECK(!memcmp(&saved, icl_snapshot_get(l, NULL), sizeof saved));
    OK(icl_set_limits(l, icl_default_limits()));
    OK(icl_reconcile(l));
    CHECK(!oracle_content(l, "a.txt", "new", 3));
    CHECK(!oracle_check(l));

    const icl_probe probes[] = {ICL_PROBE_SYMLINK, ICL_PROBE_HARDLINK, ICL_PROBE_FIFO};
    const char *names[] = {"bad-link", "bad-hard", "bad-fifo"};
    for (size_t i = 0; i < 3; i++) {
        saved = *icl_snapshot_get(l, NULL);
        OK(icl_writer_begin(l, &a));
        OK(icl_writer_probe(l, a, probes[i]));
        OK(icl_writer_end(l, a));
        CHECK(icl_reconcile(l) == ICL_INVALID);
        CHECK(icl_snapshot_get(l, &state)->generation == saved.generation && state != ICL_STATE_CURRENT);
        CHECK(!memcmp(&saved, icl_snapshot_get(l, NULL), sizeof saved));
        OK(icl_writer_begin(l, &a));
        OK(icl_writer_remove(l, a, names[i]));
        OK(icl_writer_end(l, a));
        OK(icl_reconcile(l));
        CHECK(!oracle_check(l));
    }
    OK(icl_writer_begin(l, &a));
    OK(icl_writer_mkdir(l, a, "watched"));
    OK(icl_writer_end(l, a));
    OK(icl_reconcile(l));
    uint64_t instance = icl_get_evidence(l)->instance_generation;
    OK(icl_writer_begin(l, &a));
    OK(icl_writer_remove(l, a, "watched"));
    OK(icl_writer_mkdir(l, a, "watched"));
    OK(icl_writer_end(l, a));
    CHECK(icl_consume_events(l) == ICL_DIRTY);
    OK(icl_reconcile(l));
    CHECK(icl_get_evidence(l)->instance_generation > instance);
    CHECK(!oracle_check(l));
    OK(icl_writer_begin(l, &a));
    OK(icl_writer_put(l, a, "lost", "event", 5, 0));
    OK(icl_writer_end(l, a));
    CHECK(icl_discard_events(l) == ICL_DIRTY);
    CHECK(icl_get_evidence(l)->simulated_overflows == 0);
    OK(icl_reconcile(l));
    CHECK(!oracle_content(l, "lost", "event", 5));
    CHECK(!oracle_check(l));
    OK(icl_destroy(l, &e));
    return 0;
failed:
    if (l && icl_destroy(l, &e) != ICL_OK) fputs("cleanup failed\n", stderr);
    return -1;
}

static int namespace_limits(void)
{
    icl *l = NULL;
    icl_error e;
    uint64_t t;
    OK(icl_create(&l, &e));
    OK(icl_writer_begin(l, &t));
    const char *bad[] = {"../escape", "/tmp/file", "a//b", "a/../b", ".hidden", "a/", "a\\b", "caf\xc3\xa9"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(icl_writer_put(l, t, bad[i], "x", 1, 0) == ICL_INVALID);
    char oversized[ICL_MAX_FILE_BYTES + 1u];
    memset(oversized, 's', sizeof oversized);
    CHECK(icl_writer_put(l, t, "large", oversized, sizeof oversized, 0) == ICL_INVALID);
    OK(icl_writer_put(l, t, "full", oversized, ICL_MAX_FILE_BYTES, 0));
    CHECK(icl_writer_put(l, t, "full", "x", 1, 1) == ICL_INCOMPLETE);
    OK(icl_writer_remove(l, t, "full"));
    OK(icl_writer_mkdir(l, t, "one"));
    OK(icl_writer_mkdir(l, t, "one/two"));
    OK(icl_writer_mkdir(l, t, "one/two/three"));
    CHECK(icl_writer_put(l, t, "one/two/three/f", "x", 1, 0) == ICL_INVALID);
    OK(icl_writer_put(l, t, "one/two/f", "x", 1, 0));
    CHECK(icl_writer_rename(l, t, "one", "one/two/three/deep") == ICL_INVALID);
    OK(icl_writer_end(l, t));
    OK(icl_reconcile(l));
    CHECK(!oracle_check(l));
    OK(icl_destroy(l, &e));
    l = NULL;

    OK(icl_create(&l, &e));
    OK(icl_writer_begin(l, &t));
    for (unsigned i = 0; i < ICL_MAX_DIRS; i++) {
        char name[16];
        (void)snprintf(name, sizeof name, "d%03u", i);
        OK(icl_writer_mkdir(l, t, name));
    }
    CHECK(icl_writer_mkdir(l, t, "extra") == ICL_INCOMPLETE);
    OK(icl_writer_end(l, t));
    OK(icl_reconcile(l));
    CHECK(icl_snapshot_get(l, NULL)->directories == ICL_MAX_DIRS);
    CHECK(!oracle_check(l));
    OK(icl_destroy(l, &e));
    l = NULL;

    OK(icl_create(&l, &e));
    OK(icl_writer_begin(l, &t));
    for (unsigned i = 0; i < ICL_MAX_ENTRIES; i++) {
        char name[16];
        (void)snprintf(name, sizeof name, "f%03u", i);
        OK(icl_writer_put(l, t, name, oversized, ICL_MAX_FILE_BYTES, 0));
    }
    CHECK(icl_writer_put(l, t, "extra", "", 0, 0) == ICL_INCOMPLETE);
    CHECK(icl_writer_probe(l, t, ICL_PROBE_SYMLINK) == ICL_INCOMPLETE);
    OK(icl_writer_end(l, t));
    OK(icl_reconcile(l));
    CHECK(icl_snapshot_get(l, NULL)->files == ICL_MAX_ENTRIES);
    CHECK(icl_snapshot_get(l, NULL)->bytes == ICL_MAX_TOTAL_BYTES);
    CHECK(!oracle_check(l));
    OK(icl_destroy(l, &e));
    return 0;
failed:
    if (l && icl_destroy(l, &e) != ICL_OK) fputs("cleanup failed\n", stderr);
    return -1;
}

int main(void)
{
    if (getuid() == 0 || geteuid() == 0) {
        fputs("tests require a non-root account\n", stderr);
        return 1;
    }
    scenario_report report;
    if (scenario_run(&report) || protocols_and_failures() || namespace_limits()) return 1;
    puts("All synthetic convergence, protocol, native-failure and limit tests passed.");
    return 0;
}
