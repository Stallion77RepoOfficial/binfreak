#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>
#include "format.h"
#include "coverage.h"

void fuzz_target(const char *binary_path, const char *input);
void fuzz_target_with_progress(const char *binary_path, int iterations);
void fuzz_target_with_coverage_guidance(const char *binary_path, int iterations);
void set_target_format(BinaryFormat format);
const char* get_signal_name_by_format(int signal, BinaryFormat format);

#endif
