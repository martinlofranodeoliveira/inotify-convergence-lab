#include "scenario.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void hex_digest(const unsigned char hash[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 15u];
    }
    out[64] = 0;
}

int main(int argc, char **argv)
{
    int json = argc == 2 && !strcmp(argv[1], "--json");
    if (argc > 2 || (argc == 2 && !json)) {
        fputs("usage: icl-demo [--json]\n", stderr);
        return 2;
    }
    scenario_report report;
    if (scenario_run(&report)) return 1;
    if (json) {
        printf("{\"development_version\":\"%s\",\"assertions\":\"passed\",\"stages\":[", ICL_VERSION);
        for (unsigned i = 0; i < SCENARIO_STAGES; i++) {
            const scenario_stage *s = &report.stage[i];
            printf("%s{\"name\":\"%s\",\"files\":%" PRIu64 ",\"directories\":%" PRIu64
                   ",\"bytes\":%" PRIu64 ",\"simulated_overflow\":%s}",
                   i ? "," : "", s->name, s->files, s->directories, s->bytes,
                   s->simulated_overflow ? "true" : "false");
        }
        fputs("],\"negative_checks\":{\"native_watch_failure\":true,\"symlink_rejected\":true,\"event_budget_exceeded\":true},\"final_files\":[", stdout);
        for (unsigned i = 0; i < 2; i++) {
            char digest[65];
            hex_digest(report.final_files[i].sha256, digest);
            printf("%s{\"path\":\"%s\",\"size\":%" PRIu64 ",\"sha256\":\"%s\"}",
                   i ? "," : "", report.final_files[i].path, report.final_files[i].size, digest);
        }
        puts("]}");
    } else {
        printf("Inotify Convergence Lab %s (development)\n", ICL_VERSION);
        for (unsigned i = 0; i < SCENARIO_STAGES; i++) {
            const scenario_stage *s = &report.stage[i];
            printf("%s: current files=%" PRIu64 " directories=%" PRIu64 " bytes=%" PRIu64 "%s\n",
                   s->name, s->files, s->directories, s->bytes,
                   s->simulated_overflow ? " overflow=simulated" : "");
        }
        puts("Native watch failure, symlink rejection and event-budget exhaustion: checked");
        puts("Independent oracle and content assertions: passed");
    }
    if (fflush(stdout) == EOF || ferror(stdout)) {
        fputs("output failed\n", stderr);
        return 1;
    }
    return 0;
}
