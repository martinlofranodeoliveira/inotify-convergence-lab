#ifndef ICL_H
#define ICL_H

#include <stddef.h>
#include <stdint.h>

#define ICL_VERSION "0.1.0"
#define ICL_MAX_ENTRIES 256u
#define ICL_MAX_DIRS 64u
#define ICL_MAX_DEPTH 3u
#define ICL_MAX_FILE_BYTES 4096u
#define ICL_MAX_TOTAL_BYTES 1048576u
#define ICL_PATH_CAP 99u

typedef struct icl icl;

typedef enum {
    ICL_OK = 0,
    ICL_INVALID,
    ICL_DIRTY,
    ICL_INCOMPLETE,
    ICL_NATIVE
} icl_result;

typedef enum {
    ICL_STATE_INVALID = 0,
    ICL_STATE_DIRTY,
    ICL_STATE_INCOMPLETE,
    ICL_STATE_CURRENT
} icl_state;

typedef struct {
    icl_result result;
    int native_errno;
    char operation[40];
} icl_error;

typedef struct {
    char path[ICL_PATH_CAP];
    uint64_t size;
    unsigned char sha256[32];
} icl_file;

typedef struct {
    uint64_t generation;
    uint64_t writer_epoch;
    uint64_t files;
    uint64_t directories;
    uint64_t bytes;
    icl_file file[ICL_MAX_ENTRIES];
} icl_snapshot;

typedef struct {
    uint64_t instance_generation;
    uint64_t matched_move_pairs;
    uint64_t observed_kernel_overflows;
    uint64_t simulated_overflows;
    uint64_t discarded_drains;
    uint64_t native_watch_failures;
} icl_evidence;

typedef struct {
    unsigned event_limit;
    unsigned work_limit;
    unsigned deadline_ms;
} icl_limits;

typedef enum {
    ICL_PROBE_SYMLINK,
    ICL_PROBE_HARDLINK,
    ICL_PROBE_FIFO,
    ICL_PROBE_READ_ERROR,
    ICL_PROBE_REMOVED_WATCH
} icl_probe;

/* Single-threaded serial coordinator API. See docs/contract.md. */
icl_result icl_create(icl **out, icl_error *error);
icl_result icl_destroy(icl *lab, icl_error *error);
icl_limits icl_default_limits(void);
icl_result icl_set_limits(icl *lab, icl_limits limits);
const icl_error *icl_last_error(const icl *lab);
const icl_evidence *icl_get_evidence(const icl *lab);
const icl_snapshot *icl_snapshot_get(const icl *lab, icl_state *state);

icl_result icl_writer_begin(icl *lab, uint64_t *token);
icl_result icl_writer_end(icl *lab, uint64_t token);
icl_result icl_writer_mkdir(icl *lab, uint64_t token, const char *path);
icl_result icl_writer_put(icl *lab, uint64_t token, const char *path,
                          const void *bytes, size_t length, int append);
icl_result icl_writer_rename(icl *lab, uint64_t token,
                             const char *from, const char *to);
icl_result icl_writer_quarantine(icl *lab, uint64_t token, const char *path);
icl_result icl_writer_remove(icl *lab, uint64_t token, const char *path);
/* Deliberately invalid synthetic fixtures and real native failure probes. */
icl_result icl_writer_probe(icl *lab, uint64_t token, icl_probe probe);

icl_result icl_consume_events(icl *lab);
icl_result icl_discard_events(icl *lab);
icl_result icl_simulate_overflow(icl *lab);
icl_result icl_reconcile(icl *lab);
/* An owned duplicate, for independent read-only verification; caller closes it. */
icl_result icl_oracle_root_fd(icl *lab, int *out);

#endif
