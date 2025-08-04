#ifndef DISASM_H
#define DISASM_H

#include <stdint.h>
#include <stddef.h>

void disassemble_code(uint8_t *code, size_t size, uint64_t addr);

#endif
