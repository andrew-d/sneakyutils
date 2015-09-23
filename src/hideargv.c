#define _GNU_SOURCE

#include <alloca.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "config.h"


static void my_constructor(void) __attribute__((constructor));


static void
my_constructor(void)
{
    void* p;

    printf("called\n");
    printf("  p = %p\n", &p);
}
