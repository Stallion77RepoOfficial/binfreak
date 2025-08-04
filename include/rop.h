#ifndef ROP_H
#define ROP_H

#include <mach/mach.h>
#include <stdint.h>

void find_rop_gadgets(task_t task, uint64_t rsp);
void analyze_rop_potential(const char *binary_path);

#endif
