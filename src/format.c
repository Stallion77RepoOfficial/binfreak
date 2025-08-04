#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "format.h"

BinaryFormat detect_format(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return FORMAT_UNKNOWN;

    uint8_t header[4];
    fread(header, 1, 4, f);
    fclose(f);

    if (header[0] == 0x7F && header[1] == 'E' &&
        header[2] == 'L' && header[3] == 'F')
        return FORMAT_ELF;

    if (header[0] == 0xCF && header[1] == 0xFA)
        return FORMAT_MACHO;

    if (header[0] == 'M' && header[1] == 'Z')
        return FORMAT_PE;

    return FORMAT_UNKNOWN;
}

const char* format_to_str(BinaryFormat fmt) {
    switch (fmt) {
        case FORMAT_ELF: return "ELF";
        case FORMAT_MACHO: return "Mach-O";
        case FORMAT_PE: return "PE";
        default: return "Unknown";
    }
}
