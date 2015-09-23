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

#include "pmap.h"
#include "config.h"


#define UNUSED(_x)  ((void)(_x))


#if defined(AMD64) || defined(X86)
    #define BREAKPOINT "\xCC"
#elif defined(ARM)
    /* TODO: is this accurate? */
    #define BREAKPOINT "\xFE\xDE\xFF\xE7"
#else
    #error "Unknown architecture"
#endif


/* TODO: these should be set in the configure script */
#define PRINT_SYSCALLS 0
#define SYSCALL_NUMBER_REGISTER   ORIG_RAX
#define SYSCALL_RETVAL_REGISTER   RAX


static int start_child(int argc, char **argv);
static int start_trace(pid_t child, char* progname);
static int wait_for_syscall(pid_t child);
static int find_start_addr(pid_t pid, char *mapname, uintptr_t *addr);
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
    if ((status = find_start_addr(child, procname, &start_addr)) != 0) {
        fprintf(stderr, "could not parse pmap\n");
        return status;
    }

    printf("program segment starts at: %lx\n", start_addr);

    /* TODO:
     *   1. Depending on our architecture, we should overwrite the entrypoint
     *      of the program with a breakpoint.
     *   2. Run the program until we hit the breakpoint.
     *   3. Once we have, we can use PTRACE_{PEEK,POKE}DATA to copy memory.
     *      We should copy the memory from the top of the stack to the current
     *      stack pointer "down" the stack (stacks grow down):
     *
     *          +----------+         <- top
     *          |   stuff  |
     *          |    ...   |
     *          |  argv[0] |
     *          |   argc   |         <- original stack pointer
     *          +----------+
     *          |  stuff*  |
     *          |    ...   |
     *          | argv[0]* |
     *          |   argc*  |         <- new stack pointer
     *          +----------+
     *
     *   4. Use PTRACE_POKEDATA to overwrite the original argv on the stack.
     *   5. Unset the breakpoint.
     *   6. We use PTRACE_{GET,SET}REGS to update the stack pointer and reset
     *      the instruction pointer back to the beginning of our overwritten
     *      entrypoint.
     *   7. Detach and continue the (now modified) process.
     *
     * Useful links:
     *  - http://www.linuxjournal.com/article/6210
     *  - http://mainisusuallyafunction.blogspot.com/2011/01/implementing-breakpoints-on-x86-linux.html
     */

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


struct find_start_addr_ctx {
    char*      mapname;
    uintptr_t* output;
};

static int
find_start_addr_cb(struct pmap_information *info, void *context)
{
    struct find_start_addr_ctx* ctx = (struct find_start_addr_ctx*)context;

    /* If this matches our input, then we found it. */
    if (strcmp(info->name, ctx->mapname) == 0) {
        *ctx->output = info->begin;
        return 2;
    }

    return 0;
}

/**
 * Parses /proc/<PID>/maps and returns the start address of the given mapname.
 * Returns non-zero on failure.
 */
static int
find_start_addr(pid_t pid, char *mapname, uintptr_t *addr)
{
    int ret;
    struct find_start_addr_ctx ctx;

    assert(addr != NULL);

    ctx.mapname = mapname;
    ctx.output = addr;

    ret = pmap_walk(pid, find_start_addr_cb, (void*)&ctx);
    if (ret == 2) {
        /* Success */
        return 0;
    } else if (ret < 0) {
        /* Error failure */
        /* TODO: print error? */
    }

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
