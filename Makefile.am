ACLOCAL_AMFLAGS = -I m4

#lib_LTLIBRARIES = libhideargv.la
#libhideargv_la_SOURCES = hideargv.c
#libhideargv_la_LDFLAGS = -version-info 0:0:0

bin_PROGRAMS = aspawn hello pthide

aspawn_SOURCES = aspawn.c
aspawn_CFLAGS = -Wall -Wextra -pedantic
aspawn_LDFLAGS =

hello_SOURCES = hello.c
hello_CFLAGS = -Wall -Wextra -pedantic
hello_LDFLAGS =

pthide_SOURCES = pthide.c pmap.c
pthide_CFLAGS = -Wall -Wextra -pedantic
pthide_CPPFLAGS = $(HOST_DEFINES)
pthide_LDFLAGS = -lelf
