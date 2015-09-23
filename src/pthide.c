#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
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

#include "hexdump.h"
#include "pmap.h"
#include "config.h"


#define WORD_SIZE sizeof(uintptr_t)
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
static int get_entrypoint(const char* filepath, uintptr_t *entrypoint);
static int read_proc_memory(pid_t child, uintptr_t addr, void *ptr, size_t len);
static int write_proc_memory(pid_t child, uintptr_t addr, void *ptr, size_t len);
static void dump_proc_memory(pid_t child, uintptr_t addr, size_t len);
static char* read_process_string(pid_t child, uintptr_t addr);


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
    pid_t child;

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
    child = fork();
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
    char **args = calloc(argc+1, sizeof(char*));
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
    struct pmap_information *procinfo, *stackinfo;
    uintptr_t stack_pointer;
    struct user_regs_struct regs;

    /* Wait for the child.  This returns once the child has sent itself the
     * SIGSTOP - above. */
    waitpid(child, &status, 0);

    /* Tell the process to stop on syscall-related reasons. */
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    /* Step twice - this starts and then finishes the execvp(), above. */
    if (wait_for_syscall(child) != 0) return 0;
    if (wait_for_syscall(child) != 0) return 0;

    /* Parse the /proc/<PID>/maps file for this process. */
    if ((procinfo = pmap_find_info(child, procname)) == NULL) {
        fprintf(stderr, "could not parse pmap\n");
        return 1;
    }
    if ((stackinfo = pmap_find_info(child, "[stack]")) == NULL) {
        fprintf(stderr, "could not parse pmap\n");
        return 1;
    }

    printf("program segment is at: %lx - %lx\n", procinfo->begin, procinfo->end);
    printf("stack segment is at: %lx - %lx\n", stackinfo->begin, stackinfo->end);

    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
        fprintf(stderr, "could not get process registers\n");
        return 1;
    }

#if defined(AMD64)
    stack_pointer = regs.rsp;
#elif defined(X86)
    stack_pointer = regs.esp;
#elif defined(ARM)
    stack_pointer = regs.sp;
#else
    #error "Unknown architecture"
#endif

    printf("program stack pointer is: %lx\n", stack_pointer);

    ptrdiff_t cstack_size = stackinfo->end - stack_pointer;
    printf("current stack size: 0x%lx bytes\n", cstack_size);
    printf("original stack:\n------------------------------\n");
    dump_proc_memory(child, stack_pointer, cstack_size);
    printf("\n");

    char* data = malloc((size_t)cstack_size);
    if (!data) {
        fprintf(stderr, "could not allocate memory\n");
        return 1;
    }

    uintptr_t new_stack_pointer = stack_pointer - cstack_size;

    if (read_proc_memory(child, stack_pointer, data, cstack_size) != 0) {
        fprintf(stderr, "read_proc_memory failed: %d\n", errno);
        return 1;
    }
    if (write_proc_memory(child, new_stack_pointer, data, cstack_size) != 0) {
        fprintf(stderr, "write_proc_memory failed: %d\n", errno);
        return 1;
    }

    printf("new stack:\n------------------------------\n");
    dump_proc_memory(child, new_stack_pointer, cstack_size);
    printf("\n");

    /* Reset stack pointer */
#if defined(AMD64)
    regs.rsp = new_stack_pointer;
#elif defined(X86)
    regs.esp = new_stack_pointer;
#elif defined(ARM)
    regs.sp = new_stack_pointer;
#else
    #error "Unknown architecture"
#endif

    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) {
        fprintf(stderr, "could not set process registers\n");
        return 1;
    }

    printf("new stack pointer: %lx\n", new_stack_pointer);

    /* Clear the existing argv */
    int argc;
    if (read_proc_memory(child, stack_pointer, (void*)&argc, sizeof(int)) != 0) {
        fprintf(stderr, "read_proc_memory failed: %d\n", errno);
        return 1;
    }

    printf("argc = %d\n", argc);

    int i;
    uintptr_t zero = 0;
    for (i = 0; i < argc; i++) {
        uintptr_t curr_argv;

        /* Get the current argv pointer */
        if (read_proc_memory(child, stack_pointer + (WORD_SIZE * (i + 1)), (void*)&curr_argv, WORD_SIZE) != 0) {
            fprintf(stderr, "read_proc_memory failed: %d\n", errno);
            return 1;
        }
        printf(" argv[%d] = %p\n", i, curr_argv);

        /* Read the value */
        char buf[100 + 1];
        int buflen;
        if (read_proc_memory(child, curr_argv, buf, 100) != 0) {
            fprintf(stderr, "read_proc_memory failed: %d\n", errno);
            return 1;
        }
        buf[100] = '\0';
        buflen = strlen(buf);
        printf("  -> (%d) %s\n", buflen, buf);

        /* Reset it */
        memset(buf, '\0', buflen);
        if (write_proc_memory(child, curr_argv, buf, buflen) != 0) {
            fprintf(stderr, "write_proc_memory failed: %d\n", errno);
            return 1;
        }

        /* Bump the pointer on the 'new' stack down by the stack difference */
        uintptr_t new_argv = curr_argv - cstack_size;
        if (write_proc_memory(child, new_stack_pointer + (WORD_SIZE * (i + 1)), (void*)&new_argv, WORD_SIZE) != 0) {
            fprintf(stderr, "write_proc_memory failed: %d\n", errno);
            return 1;
        }

        /* Zero the original pointer if this is not argv[0] */
        if (write_proc_memory(child, stack_pointer + (WORD_SIZE * (i + 1)), (void*)&zero, WORD_SIZE) != 0) {
            fprintf(stderr, "write_proc_memory failed: %d\n", errno);
            return 1;
        }
    }

    printf("edited original stack:\n------------------------------\n");
    dump_proc_memory(child, stack_pointer, cstack_size);
    printf("\n");

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

    pmap_free(procinfo);
    pmap_free(stackinfo);

    return 0;
}


int
read_process_argv(pid_t child, uintptr_t stack_pointer, int *out_argc, char ***out_argv)
{
    int i, argc;
    char **argv = NULL;

    assert(argc != NULL);
    assert(argv != NULL);

    if (read_proc_memory(child, stack_pointer, (void*)&argc, sizeof(int)) != 0) {
        fprintf(stderr, "read_proc_memory[argc] failed: %d\n", errno);
        goto err;
    }

    printf("argc = %d\n", argc);

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
        printf("argv[%d] = %p\n", i, argv_pointer);

        /* Read the value of this pointer */
        if (read_proc_memory(child, stack_pointer + argv_offset, (void*)&argv_pointer, WORD_SIZE) != 0) {
            fprintf(stderr, "read_proc_memory[argv[%d]] failed: %d\n", i, errno);
            goto err;
        }

        /* Read the string at this address */
        argv_value = read_process_string(child, argv_pointer);
        printf("  -> %s\n", argv_value);

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


static int
write_proc_memory(pid_t child, uintptr_t addr, void *ptr, size_t len)
{
    unsigned char *input;
    int remaining_bytes, word_count, num_words;
    union u {
        uintptr_t word;
        char      bytes[WORD_SIZE];
    } data;

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


static void
dump_proc_memory(pid_t child, uintptr_t addr, size_t len)
{
    char* buf = malloc(len);
    if (!buf) return;
    if (read_proc_memory(child, addr, buf, len) != 0) return;

    hexdump(stdout, buf, len);
    free(buf);
}


static char*
read_process_string(pid_t child, uintptr_t addr)
{
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
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
