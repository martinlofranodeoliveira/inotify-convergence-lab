#include "scenario.h"
#include "oracle.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(expr) do { if (!(expr)) { \
    fprintf(stderr, "scenario failed at line %d\n", __LINE__); goto failed; \
} } while (0)
#define OK(expr) REQUIRE((expr) == ICL_OK)

static int record(icl *l, scenario_report *r, unsigned index, const char *name,
                  uint64_t files, uint64_t dirs, uint64_t bytes, int simulated)
{
    if (icl_reconcile(l) != ICL_OK || oracle_check(l)) return -1;
    icl_state state;
    const icl_snapshot *s = icl_snapshot_get(l, &state);
    if (state != ICL_STATE_CURRENT || s->files != files ||
        s->directories != dirs || s->bytes != bytes) return -1;
    r->stage[index] = (scenario_stage){name, files, dirs, bytes, simulated};
    return 0;
}

int scenario_run(scenario_report *report)
{
    icl *l = NULL;
    icl_error error;
    uint64_t t;
    memset(report, 0, sizeof *report);
    OK(icl_create(&l, &error));
    OK(icl_writer_begin(l, &t));
    OK(icl_writer_mkdir(l, t, "sub"));
    OK(icl_writer_put(l, t, "a.txt", "ab", 2, 0));
    OK(icl_writer_put(l, t, "sub/b.txt", "x", 1, 0));
    OK(icl_writer_end(l, t));
    REQUIRE(!record(l, report, 0, "initial", 2, 1, 3, 0));
    REQUIRE(!oracle_content(l, "a.txt", "ab", 2));
    REQUIRE(!oracle_content(l, "sub/b.txt", "x", 1));
    static const unsigned char ab_hash[32] = {
        0xfb,0x8e,0x20,0xfc,0x2e,0x4c,0x3f,0x24,0x8c,0x60,0xc3,0x9b,0xd6,0x52,0xf3,0xc1,
        0x34,0x72,0x98,0xbb,0x97,0x7b,0x8b,0x4d,0x59,0x03,0xb8,0x50,0x55,0x62,0x06,0x03
    };
    REQUIRE(!memcmp(icl_snapshot_get(l, NULL)->file[0].sha256, ab_hash, 32));

    OK(icl_writer_begin(l, &t));
    OK(icl_writer_rename(l, t, "a.txt", "sub/c.txt"));
    OK(icl_writer_put(l, t, "sub/b.txt", "yz", 2, 1));
    OK(icl_writer_end(l, t));
    REQUIRE(icl_consume_events(l) == ICL_DIRTY);
    REQUIRE(!record(l, report, 1, "rename-append", 2, 1, 5, 0));
    REQUIRE(!oracle_content(l, "sub/b.txt", "xyz", 3));
    REQUIRE(!oracle_content(l, "sub/c.txt", "ab", 2));

    OK(icl_writer_begin(l, &t));
    OK(icl_writer_put(l, t, "replacement.tmp", "Q", 1, 0));
    OK(icl_writer_rename(l, t, "replacement.tmp", "sub/c.txt"));
    OK(icl_writer_end(l, t));
    REQUIRE(!record(l, report, 2, "replacement", 2, 1, 4, 0));
    REQUIRE(!oracle_content(l, "sub/c.txt", "Q", 1));
    const icl_snapshot *s = icl_snapshot_get(l, NULL);
    for (uint64_t i = 0; i < s->files; i++) REQUIRE(memcmp(s->file[i].sha256, ab_hash, 32));

    OK(icl_writer_begin(l, &t));
    OK(icl_writer_rename(l, t, "sub", "renamed"));
    OK(icl_writer_end(l, t));
    REQUIRE(!record(l, report, 3, "directory-rename", 2, 1, 4, 0));
    s = icl_snapshot_get(l, NULL);
    REQUIRE(!strcmp(s->file[0].path, "renamed/b.txt"));
    REQUIRE(!strcmp(s->file[1].path, "renamed/c.txt"));

    uint64_t pairs = icl_get_evidence(l)->matched_move_pairs;
    OK(icl_writer_begin(l, &t));
    OK(icl_writer_quarantine(l, t, "renamed/b.txt"));
    OK(icl_writer_end(l, t));
    REQUIRE(icl_consume_events(l) == ICL_DIRTY);
    REQUIRE(icl_get_evidence(l)->matched_move_pairs == pairs);
    REQUIRE(!record(l, report, 4, "quarantine", 1, 1, 1, 0));
    REQUIRE(!strcmp(icl_snapshot_get(l, NULL)->file[0].path, "renamed/c.txt"));

    OK(icl_writer_begin(l, &t));
    OK(icl_writer_put(l, t, "renamed/c.txt", "1234", 4, 0));
    OK(icl_writer_put(l, t, "d.txt", "z", 1, 0));
    OK(icl_writer_end(l, t));
    REQUIRE(icl_discard_events(l) == ICL_DIRTY);
    OK(icl_simulate_overflow(l));
    REQUIRE(!record(l, report, 5, "simulated-overflow-recovery", 2, 1, 5, 1));
    REQUIRE(icl_get_evidence(l)->simulated_overflows == 1);
    REQUIRE(!oracle_content(l, "renamed/c.txt", "1234", 4));
    REQUIRE(!oracle_content(l, "d.txt", "z", 1));

    uint64_t generation = icl_snapshot_get(l, NULL)->generation;
    OK(icl_writer_begin(l, &t));
    REQUIRE(icl_writer_probe(l, t, ICL_PROBE_REMOVED_WATCH) == ICL_NATIVE);
    REQUIRE(icl_last_error(l)->native_errno == ENOENT);
    icl_state state;
    REQUIRE(icl_snapshot_get(l, &state)->generation == generation && state != ICL_STATE_CURRENT);
    REQUIRE(icl_reconcile(l) == ICL_INVALID);
    OK(icl_writer_end(l, t));
    REQUIRE(!record(l, report, 6, "native-watch-recovery", 2, 1, 5, 0));
    report->native_watch_failure = 1;

    OK(icl_writer_begin(l, &t));
    OK(icl_writer_probe(l, t, ICL_PROBE_SYMLINK));
    OK(icl_writer_end(l, t));
    REQUIRE(icl_reconcile(l) == ICL_INVALID);
    REQUIRE(icl_snapshot_get(l, &state)->bytes == 5 && state == ICL_STATE_INCOMPLETE);
    OK(icl_writer_begin(l, &t));
    OK(icl_writer_remove(l, t, "bad-link"));
    OK(icl_writer_end(l, t));
    REQUIRE(!record(l, report, 7, "symlink-recovery", 2, 1, 5, 0));
    report->rejected_symlink = 1;

    icl_limits limits = icl_default_limits();
    limits.event_limit = 1;
    OK(icl_set_limits(l, limits));
    OK(icl_writer_begin(l, &t));
    OK(icl_writer_put(l, t, "one.tmp", "1", 1, 0));
    OK(icl_writer_put(l, t, "two.tmp", "2", 1, 0));
    OK(icl_writer_remove(l, t, "one.tmp"));
    OK(icl_writer_remove(l, t, "two.tmp"));
    OK(icl_writer_end(l, t));
    REQUIRE(icl_consume_events(l) == ICL_INCOMPLETE);
    REQUIRE(icl_snapshot_get(l, &state)->bytes == 5 && state != ICL_STATE_CURRENT);
    OK(icl_set_limits(l, icl_default_limits()));
    REQUIRE(!record(l, report, 8, "event-budget-recovery", 2, 1, 5, 0));
    report->exhausted_event_budget = 1;
    s = icl_snapshot_get(l, NULL);
    report->final_files[0] = s->file[0];
    report->final_files[1] = s->file[1];
    OK(icl_destroy(l, &error));
    return 0;
failed:
    if (l) {
        const icl_error *e = icl_last_error(l);
        fprintf(stderr, "operation=%s result=%d native_errno=%d\n", e->operation, (int)e->result, e->native_errno);
        if (icl_destroy(l, &error) != ICL_OK) fprintf(stderr, "fixture cleanup failed\n");
    }
    return -1;
}
