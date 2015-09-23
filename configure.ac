AC_PREREQ([2.64])

AC_INIT([sneakyutils],[0.0.1],[andrew@du.nham.ca])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

echo
echo "$PACKAGE_STRING"

echo
echo "System type:"
AC_CANONICAL_HOST

echo
echo "Initializing Automake:"
AM_INIT_AUTOMAKE([1.9 foreign])
AC_PROG_CC

echo
echo "Initializing Libtool:"
LT_PREREQ([2.4.6])
LT_INIT([])


###############################################################################
# Create the makefiles and config.h
###############################################################################

# Add default AM_CFLAGS.
AC_SUBST([AM_CFLAGS])

AC_CONFIG_FILES([
    Makefile
])

# Write output
AC_OUTPUT
