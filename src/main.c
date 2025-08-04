#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "format.h"
#include "fuzz.h"
#include "inputgen.h"
#include "crash.h"

// Global variable for target binary path
char* target_binary_path = NULL;

int main(int argc, char *argv[]) {
    const char *target = NULL;
    int iterations = 1000; // Default
    int use_coverage_guided = 0; // Default to classic fuzzing
    int mutation_intensity = 7; // Default mutation intensity (1-10)
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-i iterations] [-c] [-m intensity] <target_binary>\n", argv[0]);
            printf("  -i, --iterations: Number of fuzzing iterations (default: 1000)\n");
            printf("  -c, --coverage: Enable coverage-guided fuzzing (requires ptrace)\n");
            printf("  -m, --mutation: Set mutation intensity (1-10, default: 7)\n");
            printf("  -h, --help: Show this help message\n");
            printf("\nExamples:\n");
            printf("  %s vulnerable_test                    # Classic fuzzing\n", argv[0]);
            printf("  %s -c vulnerable_test                 # Coverage-guided fuzzing\n", argv[0]);
            printf("  %s -i 50 vulnerable_test              # Classic with 50 iterations\n", argv[0]);
            printf("  %s -c -i 100 vulnerable_test          # Coverage-guided with 100 iterations\n", argv[0]);
            printf("  %s -m 10 vulnerable_test              # Maximum mutation intensity\n", argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--iterations") == 0) {
            if (i + 1 < argc) {
                iterations = atoi(argv[i + 1]);
                if (iterations <= 0) {
                    printf("Error: Invalid iteration count: %s\n", argv[i + 1]);
                    return 1;
                }
                i++; // Skip next argument
            } else {
                printf("Error: Missing iteration count after %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--coverage") == 0) {
            use_coverage_guided = 1;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mutation") == 0) {
            if (i + 1 < argc) {
                mutation_intensity = atoi(argv[i + 1]);
                if (mutation_intensity < 1 || mutation_intensity > 10) {
                    printf("Error: Mutation intensity must be between 1-10, got: %s\n", argv[i + 1]);
                    return 1;
                }
                i++; // Skip next argument
            } else {
                printf("Error: Missing mutation intensity value after %s\n", argv[i]);
                return 1;
            }
        } else if (argv[i][0] != '-') {
            // This is the target binary
            if (target == NULL) {
                target = argv[i];
            } else {
                printf("Error: Multiple target binaries specified\n");
                return 1;
            }
        } else {
            printf("Error: Unknown option: %s\n", argv[i]);
            printf("Use -h or --help for usage information\n");
            return 1;
        }
    }
    
    if (target == NULL) {
        printf("Error: No target binary specified\n");
        printf("Usage: %s [-i iterations] <target_binary>\n", argv[0]);
        printf("Use -h or --help for more information\n");
        return 1;
    }

    BinaryFormat fmt = detect_format(target);
    printf("[*] Target: %s\n", target);
    printf("[*] Format: %s\n", format_to_str(fmt));
    printf("[*] Iterations: %d\n", iterations);
    printf("[*] Mode: %s\n", use_coverage_guided ? "Coverage-guided (ptrace)" : "Classic fuzzing");
    printf("[*] Mutation Intensity: %d/10\n", mutation_intensity);
    printf("[*] Initializing fuzzing engine...\n");

    // Set target binary path for crash analysis
    target_binary_path = (char*)target;

    // Set target format for platform-specific signal handling
    set_target_format(fmt);

    // Initialize advanced fuzzing engine with professional settings
    FuzzingConfig config = {
        .strategy = STRATEGY_HYBRID,
        .mutation_intensity = mutation_intensity,  // Use user-specified intensity
        .payload_focus = 1,
        .structure_awareness = 1,
        .dictionary_usage = 1
    };
    init_advanced_fuzzing(&config);

    srand(time(NULL));
    
    // Choose fuzzing mode based on user preference
    if (use_coverage_guided) {
        printf("[*] Starting coverage-guided fuzzing with dynamic instrumentation...\n");
        fuzz_target_with_coverage_guidance(target, iterations);
    } else {
        printf("[*] Starting classic fuzzing...\n");
        fuzz_target_with_progress(target, iterations);
    }

    return 0;
}
