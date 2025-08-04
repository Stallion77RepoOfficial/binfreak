#include "inputgen.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// Advanced mutation techniques for professional fuzzing

// Magic value arrays for different data types
static const uint32_t magic_32[] = {
    0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x00000004,
    0x7FFFFFFE, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF,
    0x00010000, 0x00020000, 0x00030000, 0x00040000, 0x00050000,
    0x41414141, 0x42424242, 0x43434343, 0x44444444  // ASCII patterns
};

static const uint64_t magic_64[] = {
    0x0000000000000000ULL, 0x0000000000000001ULL, 0x7FFFFFFFFFFFFFFFULL,
    0x8000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL,
    0x4141414141414141ULL, 0x4242424242424242ULL  // ASCII patterns
};
// Used in mutation_smart_arithmetic function

// SQL injection patterns
static const char *sql_payloads[] = {
    "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users --",
    "admin'--", "admin'/*", "' OR 1=1#", "' OR 'a'='a", "') OR ('1'='1"
};

// XSS patterns
static const char *xss_payloads[] = {
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')", "<svg onload=alert('XSS')>",
    "'-alert('XSS')-'", "\"><script>alert('XSS')</script>"
};

// Path traversal patterns
static const char *path_payloads[] = {
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f", "....//....//....//",
    "%252e%252e%252f", "..%c0%af..%c0%af..%c0%af"
};

// Format string patterns
static const char *format_payloads[] = {
    "%x%x%x%x%x%x%x%x", "%s%s%s%s%s%s%s%s", "%d%d%d%d%d%d%d%d",
    "%n%n%n%n%n%n%n%n", "%p%p%p%p%p%p%p%p", 
    "%08x.%08x.%08x.%08x", "%x%s%x%s%x%s%x%s"
};

// Integer overflow patterns
static const char *overflow_patterns[] = {
    "\xFF\xFF\xFF\xFF", "\x7F\xFF\xFF\xFF", "\x80\x00\x00\x00",
    "\x00\x00\x00\x80", "\xFF\xFF\xFF\x7F", "\x01\x00\x00\x80"
};

// Advanced bit manipulation mutations
void mutation_advanced_bit_flip(char *input, size_t len) {
    if (len == 0) return;
    
    int technique = rand() % 5;
    
    switch (technique) {
        case 0: // Single bit flip
            {
                int bit_pos = rand() % (len * 8);
                int byte_pos = bit_pos / 8;
                int bit_offset = bit_pos % 8;
                input[byte_pos] ^= (1 << bit_offset);
            }
            break;
            
        case 1: // Multi-bit flip (2-4 bits)
            {
                int flip_count = 2 + rand() % 3;
                for (int i = 0; i < flip_count; i++) {
                    int bit_pos = rand() % (len * 8);
                    int byte_pos = bit_pos / 8;
                    int bit_offset = bit_pos % 8;
                    input[byte_pos] ^= (1 << bit_offset);
                }
            }
            break;
            
        case 2: // Byte flip
            {
                int byte_pos = rand() % len;
                input[byte_pos] ^= 0xFF;
            }
            break;
            
        case 3: // Word flip (16-bit)
            if (len >= 2) {
                int pos = rand() % (len - 1);
                uint16_t *word = (uint16_t *)&input[pos];
                *word ^= 0xFFFF;
            }
            break;
            
        case 4: // Dword flip (32-bit)
            if (len >= 4) {
                int pos = rand() % (len - 3);
                uint32_t *dword = (uint32_t *)&input[pos];
                *dword ^= 0xFFFFFFFF;
            }
            break;
    }
}

// Smart arithmetic mutations
void mutation_smart_arithmetic(char *input, size_t len) {
    if (len == 0) return;
    
    int technique = rand() % 4;
    
    switch (technique) {
        case 0: // 8-bit arithmetic
            {
                int pos = rand() % len;
                int operation = rand() % 4;
                int value = (rand() % 35) + 1; // 1-35
                
                switch (operation) {
                    case 0: input[pos] += value; break;
                    case 1: input[pos] -= value; break;
                    case 2: input[pos] *= (value % 4) + 1; break;
                    case 3: if (value != 0) input[pos] /= value; break;
                }
            }
            break;
            
        case 1: // 16-bit arithmetic
            if (len >= 2) {
                int pos = rand() % (len - 1);
                uint16_t *val = (uint16_t *)&input[pos];
                int operation = rand() % 4;
                uint16_t operand = (rand() % 35) + 1;
                
                switch (operation) {
                    case 0: *val += operand; break;
                    case 1: *val -= operand; break;
                    case 2: *val *= (operand % 4) + 1; break;
                    case 3: if (operand != 0) *val /= operand; break;
                }
            }
            break;
            
        case 2: // 32-bit arithmetic
            if (len >= 4) {
                int pos = rand() % (len - 3);
                uint32_t *val = (uint32_t *)&input[pos];
                int operation = rand() % 4;
                uint32_t operand = (rand() % 35) + 1;
                
                switch (operation) {
                    case 0: *val += operand; break;
                    case 1: *val -= operand; break;
                    case 2: *val *= (operand % 4) + 1; break;
                    case 3: if (operand != 0) *val /= operand; break;
                }
            }
            break;
            
        case 3: // Boundary values
            {
                int pos = rand() % len;
                int boundary_type = rand() % 8;
                
                switch (boundary_type) {
                    case 0: input[pos] = 0x00; break;
                    case 1: input[pos] = 0x01; break;
                    case 2: input[pos] = 0x7F; break;
                    case 3: input[pos] = 0x80; break;
                    case 4: input[pos] = 0xFF; break;
                    case 5: input[pos] = 0xFE; break;
                    case 6: input[pos] = 0x20; break; // Space
                    case 7: input[pos] = 0x0A; break; // Newline
                }
            }
            break;
    }
}

// Vulnerability-specific payload injection
void mutation_payload_injection(char *input, size_t len) {
    if (len < 10) return; // Need minimum space
    
    int payload_type = rand() % 5;
    int pos = rand() % (len / 2); // Insert in first half
    
    const char *payload = NULL;
    size_t payload_len = 0;
    
    switch (payload_type) {
        case 0: // SQL injection
            {
                int idx = rand() % (sizeof(sql_payloads) / sizeof(sql_payloads[0]));
                payload = sql_payloads[idx];
                payload_len = strlen(payload);
            }
            break;
            
        case 1: // XSS
            {
                int idx = rand() % (sizeof(xss_payloads) / sizeof(xss_payloads[0]));
                payload = xss_payloads[idx];
                payload_len = strlen(payload);
            }
            break;
            
        case 2: // Path traversal
            {
                int idx = rand() % (sizeof(path_payloads) / sizeof(path_payloads[0]));
                payload = path_payloads[idx];
                payload_len = strlen(payload);
            }
            break;
            
        case 3: // Format string
            {
                int idx = rand() % (sizeof(format_payloads) / sizeof(format_payloads[0]));
                payload = format_payloads[idx];
                payload_len = strlen(payload);
            }
            break;
            
        case 4: // Integer overflow
            {
                int idx = rand() % (sizeof(overflow_patterns) / sizeof(overflow_patterns[0]));
                payload = overflow_patterns[idx];
                payload_len = 4; // Fixed size patterns
            }
            break;
    }
    
    if (payload && pos + payload_len < len) {
        memcpy(&input[pos], payload, payload_len);
    }
}

// Structure-aware mutations (for protocols/file formats)
void mutation_structure_aware(char *input, size_t len) {
    if (len < 8) return;
    
    int technique = rand() % 4;
    
    switch (technique) {
        case 0: // Header corruption
            {
                // Corrupt first 8 bytes (typical header size)
                int corruption_type = rand() % 3;
                switch (corruption_type) {
                    case 0: // Zero out
                        memset(input, 0, 8);
                        break;
                    case 1: // Fill with 0xFF
                        memset(input, 0xFF, 8);
                        break;
                    case 2: // Random corruption
                        for (int i = 0; i < 8; i++) {
                            if (rand() % 3 == 0) {
                                input[i] = rand() % 256;
                            }
                        }
                        break;
                }
            }
            break;
            
        case 1: // Length field manipulation
            if (len >= 4) {
                // Assume first 4 bytes might be length
                uint32_t *length_field = (uint32_t *)input;
                int manipulation = rand() % 5;
                
                switch (manipulation) {
                    case 0: *length_field = 0; break;
                    case 1: *length_field = 0xFFFFFFFF; break;
                    case 2: *length_field *= 2; break;
                    case 3: *length_field = len * 2; break;
                    case 4: *length_field = len / 2; break;
                }
            }
            break;
            
        case 2: // Checksum corruption
            if (len >= 8) {
                // Corrupt last 4 bytes (potential checksum)
                int pos = len - 4;
                uint32_t *checksum = (uint32_t *)&input[pos];
                *checksum = rand();
            }
            break;
            
        case 3: // Field boundary violations
            {
                // Insert data at common field boundaries
                int boundary_positions[] = {4, 8, 16, 32, 64, 128, 256};
                int boundary_count = sizeof(boundary_positions) / sizeof(boundary_positions[0]);
                
                for (int i = 0; i < boundary_count; i++) {
                    int pos = boundary_positions[i];
                    if (pos < len - 4) {
                        uint32_t *field = (uint32_t *)&input[pos];
                        *field = magic_32[rand() % (sizeof(magic_32) / sizeof(magic_32[0]))];
                    }
                }
            }
            break;
    }
}

// Feedback-driven mutation (simulated coverage guidance)
void mutation_feedback_driven(char *input, size_t len, CoverageState *coverage) {
    // This is a simplified version - real implementation would use
    // actual coverage feedback from instrumented binaries
    
    if (len == 0) return;
    
    // Simulate coverage-guided decisions
    int hot_spots[] = {0, len/4, len/2, 3*len/4, len-1};
    int hot_spot_count = 5;
    
    // Focus mutations on "interesting" areas
    int hot_spot = hot_spots[rand() % hot_spot_count];
    
    // Apply intensive mutations around hot spots
    int mutation_radius = 8;
    int start = (hot_spot - mutation_radius > 0) ? hot_spot - mutation_radius : 0;
    int end = (hot_spot + mutation_radius < len) ? hot_spot + mutation_radius : len;
    
    for (int pos = start; pos < end; pos++) {
        if (rand() % 3 == 0) { // 33% chance to mutate each byte
            int mutation_type = rand() % 3;
            switch (mutation_type) {
                case 0: input[pos] = rand() % 256; break;
                case 1: input[pos] ^= rand() % 256; break;
                case 2: input[pos] += (rand() % 10) - 5; break;
            }
        }
    }
}

// Dictionary-based smart mutation
void mutation_smart_dictionary(char *input, size_t len) {
    if (len < 4) return;
    
    // Protocol-specific keywords
    const char *http_keywords[] = {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
        "Host:", "User-Agent:", "Content-Type:", "Content-Length:",
        "Cookie:", "Authorization:", "Accept:", "Cache-Control:"
    };
    
    const char *file_extensions[] = {
        ".exe", ".dll", ".so", ".bin", ".dat", ".cfg", ".ini",
        ".jpg", ".png", ".gif", ".pdf", ".doc", ".xls", ".ppt"
    };
    
    const char *common_strings[] = {
        "admin", "root", "password", "user", "test", "default",
        "config", "temp", "tmp", "backup", "log", "debug"
    };
    
    int dict_type = rand() % 3;
    const char **dictionary = NULL;
    int dict_size = 0;
    
    switch (dict_type) {
        case 0:
            dictionary = http_keywords;
            dict_size = sizeof(http_keywords) / sizeof(http_keywords[0]);
            break;
        case 1:
            dictionary = file_extensions;
            dict_size = sizeof(file_extensions) / sizeof(file_extensions[0]);
            break;
        case 2:
            dictionary = common_strings;
            dict_size = sizeof(common_strings) / sizeof(common_strings[0]);
            break;
    }
    
    if (dictionary) {
        const char *keyword = dictionary[rand() % dict_size];
        size_t keyword_len = strlen(keyword);
        
        if (keyword_len < len) {
            int pos = rand() % (len - keyword_len);
            memcpy(&input[pos], keyword, keyword_len);
        }
    }
}

// Basic input generation functions that were missing
void generate_fuzz_input(char *buf, size_t len) {
    // Fill with random data
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256;
    }
    
    // Apply random mutations
    apply_random_mutation(buf, len);
}

void apply_random_mutation(char *input, size_t len) {
    if (len == 0) return;
    
    int mutation_type = rand() % 6;
    
    switch (mutation_type) {
        case 0:
            mutation_advanced_bit_flip(input, len);
            break;
        case 1:
            mutation_smart_arithmetic(input, len);
            break;
        case 2:
            mutation_payload_injection(input, len);
            break;
        case 3:
            mutation_structure_aware(input, len);
            break;
        case 4:
            mutation_smart_dictionary(input, len);
            break;
        case 5:
            {
                // Basic random byte flip
                int pos = rand() % len;
                input[pos] = rand() % 256;
            }
            break;
    }
}

// Advanced fuzzing engine functions
int init_advanced_fuzzing(FuzzingConfig *config) {
    if (!config) return -1;
    
    // Initialize random seed if not already done
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }
    
    return 0;
}

void generate_advanced_fuzz_input(char *buf, size_t len, FuzzingConfig *config) {
    if (!buf || len == 0) return;
    
    // Initialize with random data
    generate_fuzz_input(buf, len);
    
    if (!config) return;
    
    // Apply strategy-specific mutations
    switch (config->strategy) {
        case STRATEGY_VULNERABILITY:
            for (int i = 0; i < config->mutation_intensity; i++) {
                mutation_payload_injection(buf, len);
            }
            break;
            
        case STRATEGY_PROTOCOL_AWARE:
            for (int i = 0; i < config->mutation_intensity; i++) {
                mutation_structure_aware(buf, len);
                if (config->dictionary_usage) {
                    mutation_smart_dictionary(buf, len);
                }
            }
            break;
            
        case STRATEGY_GUIDED:
            {
                CoverageState dummy_coverage = {0};
                for (int i = 0; i < config->mutation_intensity; i++) {
                    mutation_feedback_driven(buf, len, &dummy_coverage);
                }
            }
            break;
            
        case STRATEGY_HYBRID:
        default:
            for (int i = 0; i < config->mutation_intensity; i++) {
                int technique = rand() % 5;
                switch (technique) {
                    case 0: mutation_advanced_bit_flip(buf, len); break;
                    case 1: mutation_smart_arithmetic(buf, len); break;
                    case 2: mutation_payload_injection(buf, len); break;
                    case 3: mutation_structure_aware(buf, len); break;
                    case 4: mutation_smart_dictionary(buf, len); break;
                }
            }
            break;
    }
}

void update_coverage_state(CoverageState *coverage, uint64_t *new_coverage, size_t size) {
    if (!coverage || !new_coverage) return;
    
    // Simplified coverage update - in real implementation this would
    // analyze coverage maps from instrumented binaries
    coverage->total_edges += size;
    coverage->new_edges_found = 0;
    
    if (coverage->coverage_map && coverage->map_size > 0) {
        for (size_t i = 0; i < size && i < coverage->map_size; i++) {
            if (new_coverage[i] > coverage->coverage_map[i]) {
                coverage->coverage_map[i] = new_coverage[i];
                coverage->new_edges_found++;
            }
        }
    }
}
