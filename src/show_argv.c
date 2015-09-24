#include <stdio.h>
#include <string.h>
#include <unistd.h>


int
main(int argc, char** argv)
{
    int i;

    printf("argc = %d\n", argc);
    printf("argv = %p\n", (void*)argv);

    for (i = 0; i < argc; i++) {
        printf("  argv[%d] = %p: `%s` (%ld)\n",
            i,
            (void*)argv[i],
            argv[i],
            (unsigned long)strlen(argv[i])
        );
    }

    sleep(1);
    return 0;
}
