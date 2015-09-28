AC_PREREQ([2.64])

AC_INIT([sneakyutils],[0.0.1],[andrew@du.nham.ca])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIRS([m4])

echo
echo "$PACKAGE_STRING"

echo
echo "System type:"
AC_CANONICAL_HOST

echo
echo "Initializing Automake:"
AM_INIT_AUTOMAKE([1.9 no-define foreign subdir-objects])
AC_PROG_CC

echo
echo "Initializing Libtool:"
LT_PREREQ([2.4.2])
LT_INIT([])


###############################################################################
# Parse host triplet
###############################################################################

HOST_DEFINES=""

case $host in
  *-*-linux*)  HOST_DEFINES="$HOST_DEFINES -DLINUX" ;;
  *-*-darwin*) HOST_DEFINES="$HOST_DEFINES -DDARWIN" ;;
  *)           AC_MSG_ERROR([Unsupported platform]) ;;
esac

case $host in
  x86_64-*-*)  HOST_DEFINES="$HOST_DEFINES -DAMD64" ;;
  i?86-*-*)    HOST_DEFINES="$HOST_DEFINES -DX86" ;;
  arm*-*-*)    HOST_DEFINES="$HOST_DEFINES -DARM" ;;
  *)           AC_MSG_ERROR([Unsupported architecture]) ;;
esac

AC_SUBST([HOST_DEFINES])

###############################################################################
# Create the makefiles and config.h
###############################################################################

# Add default AM_CFLAGS.
AC_SUBST([AM_CFLAGS])

# Specify makefiles
AC_CONFIG_FILES([
    Makefile
])

# Write output
echo ""
echo "Writing output:"
AC_OUTPUT
