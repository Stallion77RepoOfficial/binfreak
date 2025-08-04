#ifndef FORMAT_H
#define FORMAT_H

typedef enum {
    FORMAT_UNKNOWN,
    FORMAT_ELF,
    FORMAT_MACHO,
    FORMAT_PE
} BinaryFormat;

BinaryFormat detect_format(const char *filename);
const char* format_to_str(BinaryFormat fmt);

#endif
