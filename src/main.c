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
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-i iterations] <target_binary>\n", argv[0]);
            printf("  -i, --iterations: Number of fuzzing iterations (default: 1000)\n");
            printf("  -h, --help: Show this help message\n");
            printf("\nExamples:\n");
            printf("  %s vulnerable_test\n", argv[0]);
            printf("  %s -i 50 vulnerable_test\n", argv[0]);
            printf("  %s --iterations 100 vulnerable_test\n", argv[0]);
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
    printf("[*] Initializing fuzzing engine...\n");

    // Set target binary path for crash analysis
    target_binary_path = (char*)target;

    // Set target format for platform-specific signal handling
    set_target_format(fmt);

    // Initialize advanced fuzzing engine with professional settings
    FuzzingConfig config = {
        .strategy = STRATEGY_HYBRID,
        .mutation_intensity = 7,  // High intensity for better coverage
        .payload_focus = 1,
        .structure_awareness = 1,
        .dictionary_usage = 1
    };
    init_advanced_fuzzing(&config);

    srand(time(NULL));
    
    // Start fuzzing with progress bar
    fuzz_target_with_progress(target, iterations);

    return 0;
}
