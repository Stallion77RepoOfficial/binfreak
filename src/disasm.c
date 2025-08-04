#include "disasm.h"
#include <capstone/capstone.h>
#include <stdio.h>

void disassemble_code(uint8_t *code, size_t size, uint64_t addr) {
    csh handle;
    cs_insn *insn;
    size_t count;

#ifdef __arm64__
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return;
#else
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;
#endif

    count = cs_disasm(handle, code, size, addr, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            printf("0x%llx:\t%s\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("Failed to disassemble code\n");
    }

    cs_close(&handle);
}
