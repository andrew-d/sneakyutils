#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include <gelf.h>

#include "config.h"


#define UNUSED(_x)  ((void)(_x))


/* TODO: these should be set in the configure script */
#define PRINT_SYSCALLS 0
#define SYSCALL_NUMBER_REGISTER   ORIG_RAX
#define SYSCALL_RETVAL_REGISTER   RAX


static int start_child(int argc, char **argv);
static int start_trace(pid_t child, char* progname);
static int wait_for_syscall(pid_t child);
static int parse_pmap(pid_t pid, char* findme, uintptr_t* addr);
static int get_entrypoint(const char* filepath, uintptr_t *entrypoint);


static void
die(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(1);
}


int
main(int argc, char **argv)
{
    uintptr_t entrypoint;
    char rpath[PATH_MAX];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s prog args\n", argv[0]);
        exit(1);
    }

    /* The input path must be accessible. */
    if (access(argv[1], F_OK) == -1) {
        die("could not access: %s (should be absolute path)\n", argv[1]);
    }
    if (realpath(argv[1], rpath) == NULL) {
        die("could not get real path for: %s\n", argv[1]);
    }

    /* ELF parsing. */
    if (elf_version(EV_CURRENT) == EV_NONE) {
        die("could not initialize libelf: %s\n", elf_errmsg(-1));
    }

    if (get_entrypoint(rpath, &entrypoint) != 0) {
        die("could not get entrypoint\n");
    }

    /* Run the process. */
    pid_t child = fork();
    if (child == 0) {
        return start_child(argc-1, argv+1);
    } else {
        return start_trace(child, rpath);
    }
}


/**
 * SIGSTOP-s ourself, then exec's the given child.
 */
static int
start_child(int argc, char **argv)
{
    char *args [argc+1];
    memcpy(args, argv, argc * sizeof(char*));
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}


/**
 * Runs the ptrace loop.
 */
static int
start_trace(pid_t child, char* procname)
{
    int status, syscall, retval;
    uintptr_t start_addr;

    /* Wait for the child.  This returns once the child has sent itself the
     * SIGSTOP - above. */
    waitpid(child, &status, 0);

    /* Tell the process to stop on syscall-related reasons. */
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    /* Step twice - this starts and then finishes the execvp(), above. */
    if (wait_for_syscall(child) != 0) return 0;
    if (wait_for_syscall(child) != 0) return 0;

    /* Parse the /proc/<PID>/maps file for this process. */
    if ((status = parse_pmap(child, procname, &start_addr)) != 0) {
        fprintf(stderr, "could not parse pmap\n");
        return status;
    }

    printf("program segment starts at: %lx\n", start_addr);

#if PRINT_SYSCALLS
    /* Main ptrace loop */
    while(1) {
        /* Wait for a syscall, or break if the child has exited. */
        if (wait_for_syscall(child) != 0) break;

        /* Peek at the syscall value. */
        syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*SYSCALL_NUMBER_REGISTER);
        fprintf(stderr, "syscall(%d) = ", syscall);

        /* Wait again until the syscall is done. */
        if (wait_for_syscall(child) != 0) break;

        /* Get the syscall return value. */
        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*SYSCALL_RETVAL_REGISTER);
        fprintf(stderr, "%d\n", retval);
    }

    /* No need to detach here - we've exited */
#else
    UNUSED(retval);
    UNUSED(syscall);

    /* We need to continue the process, since it will have stopped upon exit of
     * a syscall (from above).  */
    if (ptrace(PTRACE_CONT, child, NULL, NULL) == -1) {
        fprintf(stderr, "could not continue process\n");
        return 1;
    }

    /* Wait for the child. */
    if (waitpid(child, &status, 0) == -1) {
        fprintf(stderr, "could not wait for child: %d\n", status);
        return 1;
    }

    /* Detach from the child. */
    if (ptrace(PTRACE_DETACH, child, NULL, NULL) == -1 ) {
        fprintf(stderr, "could not detach from process\n");
        return 1;
    }

    printf("finished\n");
#endif

    return 0;
}


/**
 * Waits for the given pid to continue until the next entry or exit of a
 * syscall.
 */
static int
wait_for_syscall(pid_t child)
{
    int status;

    while (1) {
        /* Tell the process to continue ... */
        ptrace(PTRACE_SYSCALL, child, 0, 0);

        /* ... and wait until ptrace signals us. */
        waitpid(child, &status, 0);

        /* If the child stopped on a syscall, we can return. */
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
            return 0;
        }

        /* If child exited, we're done. */
        if (WIFEXITED(status)) {
            return 1;
        }
    }
}


/**
 * Parses /proc/<PID>/maps and returns the start address of the given mapname.
 * Returns non-zero on failure.
 */
static int
parse_pmap(pid_t pid, char* findme, uintptr_t* addr)
{
    char fname[PATH_MAX];
    FILE* f;

    /* Open the process's map. */
    sprintf(fname, "/proc/%ld/maps", (long)pid);
    f = fopen(fname, "r");
    if (!f) {
        fprintf(stderr, "could not open %s: %s", fname, strerror(errno));
        return 1;
    }

    /* Parse each line. */
    while (!feof(f)) {
        char buf[PATH_MAX + 100], perm[5], dev[6], mapname[PATH_MAX];
        unsigned long begin, end, inode, foo;

        /* Read a line from the file. */
        if (fgets(buf, sizeof(buf), f) == 0) {
            break;
        }

        /* Parse the line */
        mapname[0] = '\0';
        sscanf(buf, "%lx-%lx %4s %lx %5s %lu %s", &begin, &end, perm,
            &foo, dev, &inode, mapname);

        /* If this matches our input, then we found it. */
        if (strcmp(mapname, findme) == 0) {
            *addr = (uintptr_t)begin;
            fclose(f);
            return 0;
        }

#if 1
        /* Print information. */
        if (strlen(mapname) > 0) {
            printf("%s (%lx - %lx)\n", mapname, begin, end);
        }
#endif
    }

    fclose(f);
    return 1;
}


/**
 * Retrieves the entrypoint of the given ELF file.
 */
static int
get_entrypoint(const char* filepath, uintptr_t* entrypoint)
{
    int i;
    int ret = 0;
    int fd = -1;
    Elf* e = NULL;
    GElf_Ehdr ehdr;

    assert(entrypoint != NULL);

    if ((fd = open(filepath, O_RDONLY, 0)) < 0) {
        fprintf(stderr, "could not open: %s\n", filepath);
        goto err;
    }

    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
        goto err;
    }

    if (elf_kind(e) != ELF_K_ELF) {
        fprintf(stderr, "input is not an ELF object: %s\n", filepath);
        goto err;
    }

    if (gelf_getehdr(e, &ehdr) == NULL) {
        fprintf(stderr, "getehdr() failed: %s\n", elf_errmsg(-1));
        goto err;
    }

    if ((i = gelf_getclass(e)) == ELFCLASSNONE) {
        fprintf(stderr, "getehdr() failed: %s\n", elf_errmsg(-1));
        goto err;
    }

#if 0
    printf("%s is a %d-bit ELF object\n", filepath,
        i == ELFCLASS32 ? 32 : 64);
    printf("  e_entry = %lx\n", ehdr.e_entry);
#endif

    *entrypoint = ehdr.e_entry;
    goto cleanup;

err:
    ret = 1;

cleanup:
    if (e != NULL) {
        elf_end(e);
    }

    if (fd >= 0) {
        close(fd);
    }

    return ret;
}
