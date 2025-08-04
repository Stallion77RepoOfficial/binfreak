#ifndef COVERAGE_H
#define COVERAGE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

// Coverage tracking structures
typedef struct {
    uint64_t addr;          // Basic block address
    uint32_t hit_count;     // How many times hit
    uint8_t is_new;         // Flag for new block discovery
} BasicBlock;

typedef struct {
    BasicBlock *blocks;     // Array of basic blocks
    size_t capacity;        // Maximum number of blocks
    size_t count;           // Current number of blocks
    uint64_t total_hits;    // Total execution count
    uint32_t new_blocks_found; // New blocks found in last run
} CoverageMap;

typedef struct {
    pid_t target_pid;       // Target process PID
    CoverageMap *map;       // Coverage map
    uint8_t is_attached;    // Attachment status
    uint64_t entry_point;   // Binary entry point
    uint64_t text_base;     // Text section base address
    uint64_t text_size;     // Text section size
} CoverageTracker;

// Core coverage functions
CoverageTracker* coverage_init(const char *binary_path);
void coverage_cleanup(CoverageTracker *tracker);

// Process control
int coverage_attach_process(CoverageTracker *tracker, const char *binary_path, char *input);
int coverage_detach_process(CoverageTracker *tracker);

// Coverage collection
int coverage_collect_single_run(CoverageTracker *tracker, const char *binary_path, char *input);
int coverage_is_input_interesting(CoverageTracker *tracker);

// Analysis functions
void coverage_print_stats(CoverageTracker *tracker);
double coverage_calculate_score(CoverageTracker *tracker);

// Utility functions
int coverage_parse_binary_info(const char *binary_path, uint64_t *entry_point, uint64_t *text_base, uint64_t *text_size);
int coverage_parse_elf_info_internal(int fd, uint64_t *entry_point, uint64_t *text_base, uint64_t *text_size);

#endif
