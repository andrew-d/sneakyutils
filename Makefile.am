ACLOCAL_AMFLAGS = -I m4

SUBDIRS = libelf-0.8.13

#lib_LTLIBRARIES = libhideargv.la
#libhideargv_la_SOURCES = src/hideargv.c
#libhideargv_la_LDFLAGS = -version-info 0:0:0

bin_PROGRAMS = aspawn hello pthide

aspawn_SOURCES = src/aspawn.c
aspawn_CFLAGS = -Wall -Wextra -pedantic
aspawn_LDFLAGS =

hello_SOURCES = src/hello.c
hello_CFLAGS = -Wall -Wextra -pedantic
hello_LDFLAGS =

pthide_SOURCES = src/hexdump.c src/pthide.c src/pmap.c
pthide_CFLAGS = -Wall -Wextra -pedantic
pthide_CPPFLAGS = -Ilibelf-0.8.13/lib $(HOST_DEFINES)
pthide_LDFLAGS = libelf-0.8.13/lib/libelf.a
