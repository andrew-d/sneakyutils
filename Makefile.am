ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = aspawn show_argv pthide

aspawn_SOURCES = src/aspawn.c
aspawn_CFLAGS = -Wall -Wextra -pedantic
aspawn_LDFLAGS =

show_argv_SOURCES = src/show_argv.c
show_argv_CFLAGS = -Wall -Wextra -pedantic
show_argv_LDFLAGS =

pthide_SOURCES = src/hexdump.c src/pthide.c src/pmap.c
pthide_CFLAGS = -Wall -Wextra -pedantic
pthide_CPPFLAGS = $(HOST_DEFINES)
pthide_LDFLAGS =
