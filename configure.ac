AC_PREREQ([2.69])
AC_INIT([crun],
        m4_esyscmd([build-aux/git-version-gen --prefix "" .tarball-version]),
        [giuseppe@scrivano.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_CONFIG_SRCDIR([src/crun.c])

AC_PROG_RANLIB
LT_INIT([disable-shared])

AM_INIT_AUTOMAKE([1.11.2 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_PROG_AWK
AC_PROG_SED
AC_PROG_CC
AM_PATH_PYTHON(3)

AC_PATH_PROG(MD2MAN, go-md2man)

AM_CONDITIONAL([HAVE_MD2MAN], [test "x$ac_cv_path_MD2MAN" != x])

AC_CHECK_HEADERS([error.h])

AC_CHECK_FUNCS(copy_file_range fgetxattr statx fgetpwent_r issetugid)

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
	AS_HELP_STRING([--disable-systemd], [Ignore systemd and disable support]))
AS_IF([test "x$enable_systemd" != "xno"], [
	AC_CHECK_HEADERS([systemd/sd-bus.h], [], [AC_MSG_ERROR([*** Missing libsystemd headers])])
	AS_IF([test "$ac_cv_header_systemd_sd_bus_h" = "yes"], [
		AC_SEARCH_LIBS(sd_bus_match_signal_async, [systemd], [AC_DEFINE([HAVE_SYSTEMD], 1, [Define if libsystemd is available])], [AC_MSG_ERROR([*** Failed to find libsystemd])])
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
            PKG_CHECK_MODULES([PYTHON], [python3], [], [AC_MSG_ERROR([*** python headers not found])])
            # configure should not touch CFLAGS/LDFLAGS but we need it to propagate it
            # to libocispec.
            CFLAGS+=" -fPIC "
            LDFLAGS+=" -fPIC "
])

dnl criu
AC_ARG_ENABLE([criu], AS_HELP_STRING([--disable-criu], [Disable CRIU based checkpoint/restore support]))
AS_IF([test "x$enable_criu" != "xno"], [
            PKG_CHECK_MODULES([CRIU], [criu >= 3.13], [have_criu="yes"], [have_criu="no"
			       AC_MSG_RESULT([CRIU headers not found, building without CRIU support])])
	    AS_IF([test "$have_criu" = "yes"], [
		   AC_DEFINE([HAVE_CRIU], 1, [Define if CRIU is available])
		   AC_SEARCH_LIBS(criu_init_opts, [criu])
	    ])
], [AC_MSG_RESULT([CRIU support disabled per user request])])

FOUND_LIBS=$LIBS
LIBS=""

dnl mount API
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([[
			#include <linux/mount.h>
			int cmd = FSCONFIG_CMD_CREATE;
		]])],
		[AC_MSG_RESULT(yes)
		 AC_DEFINE([HAVE_FSCONFIG_CMD_CREATE], 1, [Define if FSCONFIG_CMD_CREATE is available])],
		[AC_MSG_RESULT(no)])

dnl seccomp notify API
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([[
			#include <linux/seccomp.h>
			int cmd = SECCOMP_GET_NOTIF_SIZES;
		]])],
		[AC_MSG_RESULT(yes)
		 AC_DEFINE([HAVE_SECCOMP_GET_NOTIF_SIZES], 1, [Define if SECCOMP_GET_NOTIF_SIZES is available])],
		[AC_MSG_RESULT(no)])

AC_DEFINE([LIBCRUN_PUBLIC], [__attribute__((visibility("default"))) extern], [LIBCRUN_PUBLIC])
AC_SUBST([FOUND_LIBS])
AC_SUBST([CRUN_LDFLAGS])

[RPM_VERSION=$(echo $VERSION | sed -e's,^\([^-]*\).*$,\1,g')]

AC_SUBST([RPM_VERSION])

AC_CHECK_TOOL(GPERF, gperf)
if test -z "$GPERF"; then
       AC_MSG_NOTICE(gperf not found - cannot rebuild signal parser code)
fi

AC_SEARCH_LIBS([dlopen], [dl], [AC_DEFINE([HAVE_DLOPEN], 1, [Define if DLOPEN is available])]], [])

AC_SEARCH_LIBS([argp_parse], [argp], [], [AC_MSG_ERROR([*** argp functions not found - install libargp or argp_standalone])])

AM_CONDITIONAL([PYTHON_BINDINGS], [test "x$with_python_bindings" = "xyes"])
AM_CONDITIONAL([CRIU_SUPPORT], [test "x$have_criu" = "xyes"])

AC_CONFIG_FILES([Makefile rpm/crun.spec])

AC_CONFIG_SUBDIRS([libocispec])
AC_OUTPUT
