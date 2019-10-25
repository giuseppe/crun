AC_PREREQ([2.69])
AC_INIT([crun], [0.10.2], [giuseppe@scrivano.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_CONFIG_SRCDIR([src/crun.c])

AC_PROG_RANLIB
LT_INIT([disable-shared])

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_PROG_AWK
AC_PROG_SED
AC_PROG_CC
AM_PATH_PYTHON


AC_CHECK_HEADERS([error.h])

AC_CHECK_FUNCS(copy_file_range fgetxattr statx fgetpwent_r issetugid secure_getenv)

dnl libcap
AC_ARG_ENABLE([caps],
	AS_HELP_STRING([--disable-caps], [Ignore libcap and disable support]))
AS_IF([test "x$enable_caps" != "xno"], [
	AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])
	AS_IF([test "$ac_cv_header_sys_capability_h" = "yes"], [
		AC_SEARCH_LIBS(cap_from_name, [cap], [AC_DEFINE([HAVE_CAP], 1, [Define if libcap is available])], [AC_MSG_ERROR([*** libcap headers not found])])
	])
])

dnl libseccomp
AC_ARG_ENABLE([seccomp],
	AS_HELP_STRING([--disable-seccomp], [Ignore libseccomp and disable support]))
AS_IF([test "x$enable_seccomp" != "xno"], [
	AC_CHECK_HEADERS([seccomp.h], [], [AC_MSG_ERROR([*** Missing libseccomp headers])])
	AS_IF([test "$ac_cv_header_seccomp_h" = "yes"], [
		AC_SEARCH_LIBS(seccomp_rule_add, [seccomp], [AC_DEFINE([HAVE_SECCOMP], 1, [Define if seccomp is available])], [AC_MSG_ERROR([*** libseccomp headers not found])])
		AC_SEARCH_LIBS(seccomp_arch_resolve_name, [seccomp], [AC_DEFINE([SECCOMP_ARCH_RESOLVE_NAME], 1, [Define if seccomp_arch_resolve_name is available])], [ ])
	])
])

dnl libsystemd
AC_ARG_ENABLE([systemd],
	AS_HELP_STRING([--disable-systemd], [Enable systemd support]))
AS_IF([test "x$enable_systemd" != "xno"], [
	AC_CHECK_HEADERS([systemd/sd-bus.h], [], [AC_MSG_ERROR([*** Missing libsystemd headers])])
	AS_IF([test "$ac_cv_header_systemd_sd_bus_h" = "yes"], [
		AC_SEARCH_LIBS(sd_listen_fds, [systemd], [AC_DEFINE([HAVE_SYSTEMD], 1, [Define if libsystemd is available])], [AC_MSG_ERROR([*** Failed to find libsystemd])])
	])
])

dnl ebpf
AC_ARG_ENABLE([bpf],
	AS_HELP_STRING([--disable-bpf], [Ignore eBPF and disable support]))
AS_IF([test "x$enable_bpf" != "xno"], [
	AC_CHECK_HEADERS([linux/bpf.h])
	AS_IF([test "$ac_cv_header_linux_bpf_h" = "yes"], [
		AC_MSG_CHECKING(compilation for eBPF)
		AC_COMPILE_IFELSE(
			[AC_LANG_SOURCE([[
				#include <linux/bpf.h>
				int program = BPF_PROG_TYPE_CGROUP_DEVICE;
			]])],
			[AC_MSG_RESULT(yes)
			 AC_DEFINE([HAVE_EBPF], 1, [Define if eBPF is available])],
			[AC_MSG_RESULT(no)])
	])
])


AC_SEARCH_LIBS(yajl_tree_get, [yajl], [AC_DEFINE([HAVE_YAJL], 1, [Define if libyajl is available])], [AC_MSG_ERROR([*** libyajl headers not found])])
PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])

AC_ARG_WITH([python-bindings], AS_HELP_STRING([--with-python-bindings], [build the Python bindings]))
AS_IF([test "x$with_python_bindings" = "xyes"], [
            PKG_CHECK_MODULES([PYTHON], [python], [], [AC_MSG_ERROR([*** python headers not found])])
            # configure should not touch CFLAGS/LDFLAGS but we need it to propagate it
            # to libocispec.
            CFLAGS+=" -fPIC "
            LDFLAGS+=" -fPIC "
])

FOUND_LIBS=$LIBS
LIBS=""

AC_SUBST([FOUND_LIBS])
AC_SUBST([CRUN_LDFLAGS])

AC_SEARCH_LIBS([argp_parse], [argp], [], [AC_MSG_ERROR([*** argp functions not found - install libargp or argp_standalone])])

AM_CONDITIONAL([PYTHON_BINDINGS], [test "x$with_python_bindings" = "xyes"])

AC_CONFIG_FILES([Makefile rpm/crun.spec])

AC_CONFIG_SUBDIRS([libocispec])
AC_OUTPUT
