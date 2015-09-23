#include "pmap.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>


int
pmap_walk(pid_t pid, pmap_callback cb, void *context)
{
    char fname[PATH_MAX];
    FILE* f;
    int ret = 0;

    /* Open the process's map */
    sprintf(fname, "/proc/%ld/maps", (long)pid);
    f = fopen(fname, "r");
    if (!f) {
        return errno;
    }

    /* Parse each line. */
    while (!feof(f)) {
        char buf[PATH_MAX + 100], perm[5], mapname[PATH_MAX];
        struct pmap_information info;

        /* Read a line from the file. */
        if (fgets(buf, sizeof(buf), f) == 0) {
            break;
        }

        /* Parse the line */
        mapname[0] = '\0';
        sscanf(buf, "%lx-%lx %4s %lx %5s %lu %s",
            &info.begin,
            &info.end,
            perm,
            &info.offset,
            info.device,
            &info.inode,
            mapname
        );

        /* Fill in remaining information */
        info.readable = perm[0] == 'r';
        info.writable = perm[0] == 'w';
        info.executable = perm[0] == 'x';
        info.shared = perm[0] == 's';
        info.name = mapname;

        /* Call our callback */
        if ((ret = cb(&info, context)) != 0) {
            break;
        }
    }

    fclose(f);
    return ret;
}


