#ifndef CRASH_H
#define CRASH_H

#include <stdint.h>
#include <time.h>

typedef struct {
    uint64_t crash_addr;
    int signal;
    int count;
    char description[256];
    time_t timestamp;
    char severity[16];
    char crash_type[32];
} CrashInfo;

extern char* target_binary_path;

void analyze_crash(int pid);
void analyze_crashes(void);
void analyze_individual_crash(int signal, uint64_t crash_addr, int crash_id);

#endif
