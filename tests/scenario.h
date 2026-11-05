#ifndef SCENARIO_H
#define SCENARIO_H
#include "icl.h"
#define SCENARIO_STAGES 9u
typedef struct {
    const char *name;
    uint64_t files, directories, bytes;
    int simulated_overflow;
} scenario_stage;
typedef struct {
    scenario_stage stage[SCENARIO_STAGES];
    icl_file final_files[2];
    int native_watch_failure, rejected_symlink, exhausted_event_budget;
} scenario_report;
int scenario_run(scenario_report *report);
#endif
