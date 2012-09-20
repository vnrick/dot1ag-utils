#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([dot1ag-utils], [1.0.1], [rvdp@sara.nl])
AM_INIT_AUTOMAKE([-Wall -Werror foreign no-dependencies])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	doc/Makefile
])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([net/bpf.h net/if_ether.h net/ethernet.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset select socket])

AC_OUTPUT
