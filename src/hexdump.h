#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <stdint.h>
#include <stdio.h>

void hexdump(FILE * stream, void const * data, size_t len, uintptr_t start_addr);

#endif
