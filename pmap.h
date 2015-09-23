#ifndef PMAP_H
#define PMAP_H

#include <stdint.h>
#include <sys/types.h>


/* Structure containing information */
struct pmap_information {
    uintptr_t     begin;
    uintptr_t     end;
    char          readable;
    char          writable;
    char          executable;
    char          shared;
    unsigned long offset;
    char          device[6];
    unsigned long inode;
    char          *name;
} pmap_information;

/* Callback type */
typedef int (*pmap_callback)(struct pmap_information *info, void *context);

/**
 * Open the process map and calls `cb` for each entry in it.  Will return 0 on
 * success, non-zero on failure.  If `cb` returns a non-zero value, will halt
 * the traversal and return what it did.
 */
int pmap_walk(pid_t pid, pmap_callback cb, void *context);


#endif /* PMAP_H */
