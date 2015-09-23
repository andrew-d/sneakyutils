#include "pmap.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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


struct find_info_ctx {
    const char*              name;
    struct pmap_information* output;
};

static int
pmap_find_info_cb(struct pmap_information *info, void *context)
{
    struct find_info_ctx* ctx = (struct find_info_ctx*)context;

    /* If this matches our input, then we found it. */
    if (strcmp(info->name, ctx->name) == 0) {
        struct pmap_information* ret;
        ret = (struct pmap_information*)malloc(sizeof(struct pmap_information));

        /* Copy information that's constant. */
        ret->begin      = info->begin;
        ret->end        = info->end;
        ret->readable   = info->readable;
        ret->writable   = info->writable;
        ret->executable = info->executable;
        ret->shared     = info->shared;
        ret->offset     = info->offset;
        ret->inode      = info->inode;

        memcpy(&ret->device, info->device, 6);
        ret->name = strdup(info->name);

        ctx->output = ret;
        return 2;
    }

    return 0;
}


struct pmap_information*
pmap_find_info(pid_t pid, const char* name)
{
    int ret;
    struct find_info_ctx ctx;

    ctx.name = name;
    ret = pmap_walk(pid, pmap_find_info_cb, (void*)&ctx);
    if (ret == 2) {
        return ctx.output;
    }

    return NULL;
}


void
pmap_free(struct pmap_information* info)
{
    free(info->name);
    free(info);
}
