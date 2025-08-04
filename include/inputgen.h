#ifndef INPUTGEN_H
#define INPUTGEN_H

#include <stddef.h>
#include <stdint.h>

// Coverage-guided fuzzing state
typedef struct {
    uint64_t *coverage_map;
    size_t map_size;
    uint64_t total_edges;
    uint64_t new_edges_found;
} CoverageState;

// Professional fuzzing strategies
typedef enum {
    STRATEGY_RANDOM,           // Pure random mutations
    STRATEGY_GUIDED,           // Coverage-guided mutations
    STRATEGY_PROTOCOL_AWARE,   // Protocol/format-specific mutations
    STRATEGY_VULNERABILITY,    // Vulnerability-pattern focused
    STRATEGY_HYBRID           // Combination of strategies
} FuzzingStrategy;

// Fuzzing campaign configuration
typedef struct {
    FuzzingStrategy strategy;
    int mutation_intensity;    // 1-10 scale
    int payload_focus;        // Focus on specific vulnerability types
    int structure_awareness;  // Enable structure-aware mutations
    int dictionary_usage;     // Use smart dictionaries
} FuzzingConfig;

// Basic input generation functions
void generate_fuzz_input(char *buf, size_t len);
void apply_random_mutation(char *input, size_t len);

// Advanced mutation functions
void mutation_advanced_bit_flip(char *input, size_t len);
void mutation_smart_arithmetic(char *input, size_t len);
void mutation_payload_injection(char *input, size_t len);
void mutation_structure_aware(char *input, size_t len);
void mutation_feedback_driven(char *input, size_t len, CoverageState *coverage);
void mutation_smart_dictionary(char *input, size_t len);

// Advanced fuzzing engine functions
int init_advanced_fuzzing(FuzzingConfig *config);
void generate_advanced_fuzz_input(char *buf, size_t len, FuzzingConfig *config);
void update_coverage_state(CoverageState *coverage, uint64_t *new_coverage, size_t size);

#endif
