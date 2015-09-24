#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "hexdump.h"
#include "pmap.h"


#define WORD_SIZE sizeof(uintptr_t)
#define UNUSED(_x)  ((void)(_x))


#ifdef DEBUG
#   define dprintf(...) do { fprintf(stdout, __VA_ARGS__); } while (0)
#else
#   define dprintf(...) do {} while (0)
#endif


/* TODO: this should be set in the configure script */
#define DUMP_STACK 0


static int start_child();
static int start_trace(pid_t child);
static int wait_for_syscall(pid_t child);
static int read_proc_memory(pid_t child, uintptr_t addr, void *ptr, size_t len);
static int write_proc_memory(pid_t child, uintptr_t addr, void *ptr, size_t len);
static int set_proc_memory(pid_t child, uintptr_t addr, unsigned char ch, size_t len);
static int copy_proc_memory(pid_t child, uintptr_t source, uintptr_t dest, size_t len);
static void dump_proc_memory(pid_t child, uintptr_t addr, size_t len);
static char* read_process_string(pid_t child, uintptr_t addr);
static int set_process_stack_pointer(pid_t child, uintptr_t sp);
static int get_process_stack_pointer(pid_t child, uintptr_t *out);
size_t argv_size(int argc, char** argv);


/* These are the fake and real arguments, parsed from our command line */
static char **fakeargv, **realargv;
static int fakeargc, realargc;
static int maxargc;

/* The real path of the binary to run */
static char rpath[PATH_MAX];


static void
die(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(1);
}


inline int
max(int a, int b)
{
    return a > b ? a : b;
}


/* strdup a string, aligning to 16-byte allocations */
inline char*
strdup_aligned(char* s)
{
    char* dd;
    size_t slen;

    slen = strlen(s);
    slen = (slen + (0x10 - 1)) & -0x10;

    dd = calloc(slen, 1);
    if (!dd) return NULL;

    strcpy(dd, s);
    return dd;
}



int
main(int argc, char **argv)
{
    pid_t child;
    int i, j;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s fakeprog fakeargs -- realprog realargs\n", argv[0]);
        return 1;
    }

    /* Fake arguments are until the first '--' */
    fakeargv = argv + 1;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            break;
        }

        ++fakeargc;
    }

    if (i == argc) {
        fprintf(stderr, "no real arguments given\n");
        return 1;
    }

    /* Real argument are until the end */
    realargc = argc - (i + 1);
    realargv = calloc(realargc + 1, sizeof(char*));
    for (j = 0; j < realargc; j++) {
        realargv[j] = strdup_aligned(argv[i + 1 + j]);
    }

    if (fakeargc > realargc) {
        fprintf(stderr, "currently, you cannot have more fake arguments than real arguments (%d > %d)\n",
            fakeargc, realargc);
        return 1;
    }

    /* Calculate maximum number of arguments */
    maxargc = max(fakeargc, realargc);

    for (i = 0; i < fakeargc; i++) {
        dprintf("fakeargv[%d] = %s\n", i, fakeargv[i]);
    }
    for (i = 0; i < realargc; i++) {
        dprintf("realargv[%d] = %s\n", i, realargv[i]);
    }

    /* The input path must be accessible. */
    if (access(realargv[0], F_OK) == -1) {
        die("could not access: %s (should be absolute path)\n", realargv[0]);
    }
    if (realpath(realargv[0], rpath) == NULL) {
        die("could not get real path for: %s\n", realargv[0]);
    }

    /* Run the process. */
    child = fork();
    if (child == 0) {
        return start_child();
    } else {
        return start_trace(child);
    }
}


/**
 * SIGSTOP-s ourself, then exec's the given child.
 */
static int
start_child()
{
    int i;
    char **args = calloc(maxargc+1, sizeof(char*));

    /* Copy our fake args on top */
    memcpy(args, fakeargv, fakeargc * sizeof(char*));

    /* If we have more real args, those are '' */
    for (i = fakeargc; i < realargc; i++) {
        args[i] = "";
    }

    /* Null-terminate */
    args[maxargc] = NULL;

    /* Note: we're running ourself here with the FAKE argv, and the ptrace bits
     * will dump and write the 'real' argv to the process when fixing it up. */
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(realargv[0], args);
}


/**
 * Runs the ptrace loop.
 */
static int
start_trace(pid_t child)
{
    struct pmap_information *stackinfo;
    uintptr_t p, stack_pointer, new_stack_pointer, new_argc;
    ptrdiff_t stack_size, stack_diff;
    int i;
    uintptr_t zero = 0;
    uintptr_t *arg_locations;
    int status;

    /* Wait for the child.  This returns once the child has sent itself the
     * SIGSTOP - above. */
    waitpid(child, &status, 0);

    /* Tell the process to stop on syscall-related reasons. */
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    /* Step twice - this starts and then finishes the execvp(), above. */
    if (wait_for_syscall(child) != 0) return 0;
    if (wait_for_syscall(child) != 0) return 0;

    /* Parse the /proc/<PID>/maps file for this process. */
    if ((stackinfo = pmap_find_info(child, "[stack]")) == NULL) {
        fprintf(stderr, "could not parse pmap\n");
        return 1;
    }
    dprintf("stack segment is at: %lx - %lx\n", stackinfo->begin, stackinfo->end);

    if (get_process_stack_pointer(child, &stack_pointer) != 0) {
        return 1;
    }

    /* Calculate the current stack size, and the size that we're offsetting our
     * stack by. */
    stack_size = stackinfo->end - stack_pointer;
    stack_diff = stack_size + argv_size(realargc, realargv);

    /* Align the difference to 16 bytes */
    stack_diff = (stack_diff + (0x10 - 1)) & -0x10;

    dprintf("current stack size: 0x%lx bytes\n", stack_size);
    dprintf("  replacement argv: 0x%lx bytes\n", argv_size(realargc, realargv));
    dprintf("  stack difference: 0x%lx bytes\n", stack_diff);

    /* The new stack pointer is 'below' the existing one by the size
     * difference.  Stacks grow down! */
    new_stack_pointer = stack_pointer - stack_diff;

    /* Fill the stack with 0xAA for debugging */
    set_proc_memory(child, new_stack_pointer, 0xAA, stack_pointer - new_stack_pointer);

    /* Copy the old to the new */
    if (copy_proc_memory(child, stack_pointer, new_stack_pointer, stack_size) != 0) {
        fprintf(stderr, "failed to copy process memory: %d\n", errno);
        return 1;
    }

    /* Serialize the real argv into the gap between old and new.  We save the
     * pointers to the serialized locations as we go, so we can set them below. */
    arg_locations = calloc(realargc, sizeof(uintptr_t));
    p = new_stack_pointer + stack_size;
    for (i = 0; i < realargc; i++) {
        size_t slen = strlen(realargv[i]) + 1;   /* Inc. trailing null */

        if (write_proc_memory(child, p, realargv[i], slen) != 0) {
            fprintf(stderr, "write_proc_memory[realargv[%d]] failed: %d\n", i, errno);
            return 1;
        }

        dprintf("arg_locations[%d] = 0x%lx\n", i, p);
        arg_locations[i] = p;
        p += slen;
    }

    /* Reset stack pointer to the new value */
    if (set_process_stack_pointer(child, new_stack_pointer) != 0) {
        return 1;
    }

    /* Set the 'real' argc value */
    new_argc = realargc;
    if (write_proc_memory(child, new_stack_pointer, (void*)&new_argc, WORD_SIZE) != 0) {
        fprintf(stderr, "write_proc_memory[realargc] failed: %d\n", errno);
        return 1;
    }

    /* Fix up all argv pointers.  This requires us to update pointers in the
     * new argv array.  The general logic is:
     *   - If the current argument is within the real argument count, fix the
     *     new pointer to point to the right location.
     *   - If the current argument is after the real argument count, NULL the
     *     appropriate new pointer.
     * */
    for (i = 0; i < maxargc; i++) {
        ptrdiff_t argv_offset = WORD_SIZE * (i + 1);

        if (i < realargc) {
            uintptr_t new_ptr = arg_locations[i];

            dprintf("  changing to 0x%lx\n", new_ptr);

            /* Change the original pointer if we have a fake argument */
            if (write_proc_memory(child, new_stack_pointer + argv_offset, (void*)&new_ptr, WORD_SIZE) != 0) {
                fprintf(stderr, "write_proc_memory[ptr-change] failed: %d\n", errno);
                return 1;
            }
        } else {
            dprintf("  zeroing\n");

            if (write_proc_memory(child, new_stack_pointer + argv_offset, (void*)&zero, WORD_SIZE) != 0) {
                fprintf(stderr, "write_proc_memory[ptr-zero] failed: %d\n", errno);
                return 1;
            }
        }
    }

#if DUMP_STACK
    dprintf("stack dump:\n------------------------------\n");
    dump_proc_memory(child, new_stack_pointer, stackinfo->end - new_stack_pointer);
    dprintf("\n");
#else
    ((void)dump_proc_memory);
#endif

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

    dprintf("finished\n");
    pmap_free(stackinfo);
    return 0;
}


/**
 * Reads the argv of a given process, given the initial stack pointer.
 */
int
read_process_argv(pid_t child, uintptr_t stack_pointer, int *out_argc, char ***out_argv)
{
    int i, argc;
    char **argv = NULL;

    assert(out_argc != NULL);
    assert(out_argv != NULL);

    if (read_proc_memory(child, stack_pointer, (void*)&argc, sizeof(int)) != 0) {
        fprintf(stderr, "read_proc_memory[argc] failed: %d\n", errno);
        goto err;
    }

    dprintf("argc = %d\n", argc);

    /* Allocate enough space for the argv array, plus the null terminator */
    argv = (char**)calloc(argc + 1, sizeof(char*));
    if (!argv) return 1;

    /* Read each argv pointer */
    for (i = 0; i < argc; i++) {
        ptrdiff_t argv_offset;
        uintptr_t argv_pointer;
        char* argv_value;

        /* Offset to the current argv[i] on the stack */
        argv_offset = WORD_SIZE * (i + 1);

        /* Get the current argv pointer */
        if (read_proc_memory(child, stack_pointer + argv_offset, (void*)&argv_pointer, WORD_SIZE) != 0) {
            fprintf(stderr, "read_proc_memory[argv[%d]] failed: %d\n", i, errno);
            goto err;
        }
        dprintf("argv[%d] = 0x%lx\n", i, argv_pointer);

        /* Read the value of this pointer */
        if (read_proc_memory(child, stack_pointer + argv_offset, (void*)&argv_pointer, WORD_SIZE) != 0) {
            fprintf(stderr, "read_proc_memory[argv[%d]] failed: %d\n", i, errno);
            goto err;
        }

        /* Read the string at this address */
        argv_value = read_process_string(child, argv_pointer);
        dprintf("  -> %s\n", argv_value);

        /* Save for return */
        argv[i] = argv_value;
    }

    /* Done - ensure we're NULL-terminated */
    argv[argc] = NULL;
    return 0;

err:
    if (argv) {
        for (i = 0; i < argc; i++) {
            if (argv[i]) free(argv[i]);
        }

        free(argv);
    }
    return 1;
}


/**
 * Calculate the number of bytes required to serialize an argv structure
 * 'properly'.
 */
size_t
argv_size(int argc, char** argv)
{
    int i;
    size_t ret = 0;

    for (i = 0; i < argc; ++i ) {
        ret += strlen(argv[i]) + 1;
    }

    return ret;
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
 * Retrieves the process's architecture-dependent stack pointer.
 */
static int
get_process_stack_pointer(pid_t child, uintptr_t *out) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
        fprintf(stderr, "could not get process registers\n");
        return 1;
    }

#if defined(AMD64)
    *out = regs.rsp;
#elif defined(X86)
    *out = regs.esp;
#elif defined(ARM)
    *out = regs.sp;
#else
#   error "Unknown architecture"
#endif

    dprintf("program stack pointer is: %lx\n", *out);
    return 0;
}


/**
 * Sets the process's architecture-dependent stack pointer.
 */
static int
set_process_stack_pointer(pid_t child, uintptr_t sp) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
        fprintf(stderr, "could not get process registers\n");
        return 1;
    }

#if defined(AMD64)
    regs.rsp = sp;
#elif defined(X86)
    regs.esp = sp;
#elif defined(ARM)
    regs.sp = sp;
#else
#   error "Unknown architecture"
#endif

    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) {
        fprintf(stderr, "could not set process registers\n");
        return 1;
    }

    dprintf("new stack pointer: %lx\n", sp);
    return 0;
}


/**
 * Reads some number of bytes from the given process into ptr.
 */
static int
read_proc_memory(pid_t child, uintptr_t addr, void *ptr, size_t len)
{
    unsigned char *output;
    int remaining_bytes, word_count, num_words;
    union u {
        uintptr_t word;
        char      bytes[WORD_SIZE];
    } data;

    memset(ptr, 0, len);

    data.word = 0;
    word_count = 0;
    num_words = len / WORD_SIZE;
    output = (unsigned char*)ptr;

    while (word_count < num_words) {
        /* Since the return value from this is -1 on error, but the return
         * value may also be -1 on success, we need to clear and then check
         * errno. */
        errno = 0;
        data.word = ptrace(PTRACE_PEEKDATA, child, addr + word_count * WORD_SIZE, NULL);
        if (errno != 0) {
            return 1;
        }

        memcpy(output, data.bytes, WORD_SIZE);
        ++word_count;
        output += WORD_SIZE;
    }

    remaining_bytes = len % WORD_SIZE;
    if (remaining_bytes != 0) {
        /* See above for why we're doing this */
        errno = 0;
        data.word = ptrace(PTRACE_PEEKDATA, child, addr + word_count * WORD_SIZE, NULL);
        if (errno != 0) {
            return 1;
        }

        memcpy(output, data.bytes, remaining_bytes);
    }

    return 0;
}


/**
 * Writes the data from ptr into the given process at the specified address.
 */
static int
write_proc_memory(pid_t child, uintptr_t addr, void *ptr, size_t len)
{
    unsigned char *input;
    int remaining_bytes, word_count, num_words;
    union u {
        uintptr_t word;
        char      bytes[WORD_SIZE];
    } data;

    data.word = 0;
    word_count = 0;
    num_words = len / WORD_SIZE;
    input = (unsigned char*)ptr;

    while (word_count < num_words) {
        memcpy(data.bytes, input, WORD_SIZE);
        if (ptrace(PTRACE_POKEDATA, child, addr + word_count * WORD_SIZE, data.word) == -1) {
            return 1;
        }
        ++word_count;
        input += WORD_SIZE;
    }

    remaining_bytes = len % WORD_SIZE;
    if (remaining_bytes != 0) {
        memcpy(data.bytes, input, WORD_SIZE);
        if (ptrace(PTRACE_POKEDATA, child, addr + word_count * WORD_SIZE, data.word) == -1) {
            return 1;
        }
    }

    return 0;
}


/**
 * memset() for a remote process's memory
 */
static int
set_proc_memory(pid_t child, uintptr_t addr, unsigned char ch, size_t len)
{
    int ret;
    char *buf = malloc(len);
    if (!buf) return 1;

    memset(buf, ch, len);
    ret = write_proc_memory(child, addr, buf, len);
    free(buf);
    return ret;
}


/**
 * memcpy() for a remote process's memory
 */
static int
copy_proc_memory(pid_t child, uintptr_t source, uintptr_t dest, size_t len)
{
    char *buf = malloc(len);
    if (!buf) return 1;

    if (read_proc_memory(child, source, buf, len) != 0) {
        goto err;
    }
    if (write_proc_memory(child, dest, buf, len) != 0) {
        goto err;
    }

    free(buf);
    return 0;

err:
    free(buf);
    return 1;
}


/**
 * hexdump() a remote process's memory
 */
static void
dump_proc_memory(pid_t child, uintptr_t addr, size_t len)
{
    char* buf = malloc(len);
    if (!buf) return;
    if (read_proc_memory(child, addr, buf, len) != 0) return;

    hexdump(stdout, buf, len, addr);
    free(buf);
}


/**
 * Reads a string from a remote process.  The return value should be freed with
 * free().
 */
static char*
read_process_string(pid_t child, uintptr_t addr)
{
    char *val = malloc(4096);
    size_t allocated = 4096;
    size_t read = 0;
    union u {
        uintptr_t word;
        char      bytes[WORD_SIZE];
    } data;

    while (1) {
        if (read + WORD_SIZE > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }

        data.word = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }

        memcpy(val + read, data.bytes, WORD_SIZE);
        if (memchr(data.bytes, 0, WORD_SIZE) != NULL) {
            break;
        }

        read += WORD_SIZE;
    }

    return val;
}
