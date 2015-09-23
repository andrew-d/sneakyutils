/*
 * This utility is a handy tool that runs a given command and cloaks the binary
 * name.  Essentially, it execve()'s the given process and replaces argv[0]
 * with the given input.
 *
 * Note that this might break some tools that depend on this value.
 */

#include <errno.h>   /* for errno */
#include <stdarg.h>  /* for va_args, etc. */
#include <stdio.h>   /* for the *printf functions */
#include <stdlib.h>  /* for calloc and exit */
#include <string.h>  /* for strcmp */
#include <unistd.h>  /* for execve */

#include "config.h"


static void
die(const char * format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    vfprintf(stderr, format, vargs);
    exit(1);
}


int
main(int argc, char *argv[], char *envp[])
{
    int i;
    char **nargv;

    if( argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) ) {
        fprintf(
            stderr,
            "usage: %s <fake bin name> <actual bin name> <arguments>...\n",
            argv[0]
        );
        exit(0);
    }

    if( argc < 3 ) {
        die("not enough arguments - try running `%s --help` for more info\n", argv[0]);
    }

    /*
     * We create a new 'argv' array that contains:
     *   nargv[0] = fake binary name
     *   nargv[1] = argument 1
     *   nargv[2] = argument 2
     * And so on.
     *
     * The mapping from our argv to this one is as follows:
     *
     *   +---------+-----------+---------------+------+------+-----+
     *   | argv[0] | fake name | real bin name | arg1 | arg2 | NUL |
     *   +---------+-----------+---------------+------+------+-----+
     *                |                           |      |
     *         +------+  +------------------------+      |
     *         |         |      +------------------------+
     *         v         v      v
     *   +-----------+------+------+-----+
     *   | fake name | arg1 | arg2 | NUL |
     *   +-----------+------+------+-----+
     *
     * Note that we need 2 less array slots than the input argv.
     */

    nargv = calloc(argc - 2 + 1, sizeof(char*));
    if( !nargv ) {
        die("could not allocate memory");
    }

    /* The 0th entry is the fake binary name */
    nargv[0] = argv[1];

    /* Copy over remaining arguments */
    for (i = 3; i < argc; i++) {
        nargv[i-2] = argv[i];
    }

    /* Run the new process with our fake argv and original envp */
    execve(argv[2], nargv, envp);

    /* If we get here, there was an error */
    fprintf(stderr, "error in execve(): %d\n", errno);
    return 0;
}
