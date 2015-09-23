#!/bin/sh


cd `dirname $0`

AC_SEARCH_OPTS="--install -I m4"

# For those of us with pkg-config and other tools in /usr/local
PATH=$PATH:/usr/local/bin

# This is to make life easier for people who installed pkg-config in /usr/local
# but have autoconf/make/etc in /usr/ - i.e. most mac users
if [ -d "/usr/local/share/aclocal" ]
then
    AC_SEARCH_OPTS="-I /usr/local/share/aclocal"
fi

aclocal $AC_SEARCH_OPTS && \
autoconf && \
autoheader && \
automake --add-missing && \
./configure "$@"
