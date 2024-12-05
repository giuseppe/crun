AC_PREREQ([2.69])
AC_INIT([crun],
	m4_esyscmd([build-aux/git-version-gen --prefix "" .tarball-version]),
	[giuseppe@scrivano.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_CONFIG_SRCDIR([src/crun.c])

AC_PROG_LN_S

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

AC_CHECK_HEADERS([error.h linux/openat2.h stdatomic.h linux/ioprio.h])

AC_CHECK_TYPES([atomic_int], [], [], [[#include <stdatomic.h>]])

AC_CHECK_FUNCS(copy_file_range fgetxattr statx fgetpwent_r issetugid memfd_create)

AC_ARG_ENABLE(crun,
AS_HELP_STRING([--enable-crun], [Include crun executable in installation (default: yes)]),
[
case "${enableval}" in
	yes) enable_crun=true ;;
	no) enable_crun=false ;;
	*) AC_MSG_ERROR(bad value $(enableval) for --disable-crun) ;;
esac],
[enable_crun=true])
AM_CONDITIONAL([ENABLE_CRUN], [test "x${enable_crun}" = xtrue])

AC_ARG_ENABLE(libcrun,
AS_HELP_STRING([--enable-libcrun], [Include libcrun in installation (default: yes)]),
[
case "${enableval}" in
	yes) enable_libcrun=true ;;
	no) enable_libcrun=false ;;
	*) AC_MSG_ERROR(bad value ${enablevaal} for --enable-libcrun) ;;
esac
],
[enable_libcrun=true])
AM_CONDITIONAL([ENABLE_LIBCRUN], [test "x${enable_libcrun}" = xtrue])

dnl embedded yajl
AC_ARG_ENABLE(embedded-yajl,
AS_HELP_STRING([--enable-embedded-yajl], [Statically link a modified yajl version]),
[
case "${enableval}" in
	yes) embedded_yajl=true ;;
	no)  embedded_yajl=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-embedded-yajl) ;;
esac],[embedded_yajl=false])

AC_ARG_ENABLE(dynload-libcrun,
AS_HELP_STRING([--enable-dynload-libcrun], [Dynamically load libcrun]),
[
case "${enableval}" in
	yes) dynload_libcrun=true ;;
	no)  dynload_libcrun=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-dynload-libcrun) ;;
esac],[dynload_libcrun=false])
AM_CONDITIONAL([DYNLOAD_LIBCRUN], [test x"$dynload_libcrun" = xtrue])

AM_CONDITIONAL([HAVE_EMBEDDED_YAJL], [test x"$embedded_yajl" = xtrue])
AM_COND_IF([HAVE_EMBEDDED_YAJL], [], [
AC_SEARCH_LIBS(yajl_tree_get, [yajl], [AC_DEFINE([HAVE_YAJL], 1, [Define if libyajl is available])], [AC_MSG_ERROR([*** libyajl headers not found])])
PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])
])

dnl libcap
AC_ARG_ENABLE([caps],
	AS_HELP_STRING([--disable-caps], [Ignore libcap and disable support]))
AS_IF([test "x$enable_caps" != "xno"], [
	AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])
	AS_IF([test "$ac_cv_header_sys_capability_h" = "yes"], [
		AC_SEARCH_LIBS(cap_from_name, [cap], [AC_DEFINE([HAVE_CAP], 1, [Define if libcap is available])], [AC_MSG_ERROR([*** libcap headers not found])])
	])
])

dnl dl
AC_ARG_ENABLE([dl], AS_HELP_STRING([--disable-dl], [Disable dynamic libraries support]))
AS_IF([test "x$enable_dl" != "xno"], [
	AC_SEARCH_LIBS([dlopen], [dl], [AC_DEFINE([HAVE_DLOPEN], 1, [Define if DLOPEN is available])], [])
])

AC_SUBST(MONO_CFLAGS)
AC_SUBST(MONO_LIBS)
dnl include support for mono (EXPERIMENTAL)
AC_ARG_WITH([mono], AS_HELP_STRING([--with-mono], [build with mono support]))
AS_IF([test "x$with_mono" = "xyes"], [
	AC_CHECK_HEADERS([mono/metadata/environment.h], [], [AC_MSG_ERROR([*** Missing mono headers1])])
	AS_IF([test "$ac_cv_header_mono_metadata_environment_h" = "yes"], [
		AC_SEARCH_LIBS(mono_environment_exitcode_get, [mono-2.0], [AC_DEFINE([HAVE_MONO], 1, [Define if mono is available])], [AC_MSG_ERROR([*** Missing mono headers2])])
		MONO_CFLAGS=`pkg-config --cflags mono-2`
		MONO_LIBS=`pkg-config --libs mono-2`
		CFLAGS="$CFLAGS `pkg-config --cflags mono-2`"
		LIBS="$LIBS `pkg-config --libs mono-2`"
	])
])

dnl include support for wasmer (EXPERIMENTAL)
AC_ARG_WITH([wasmer], AS_HELP_STRING([--with-wasmer], [build with wasmer support]))
AS_IF([test "x$with_wasmer" = "xyes"], AC_CHECK_HEADERS([wasmer.h], AC_DEFINE([HAVE_WASMER], 1, [Define if wasmer is available]), [AC_MSG_ERROR([*** Missing wasmer headers])]))

dnl include support for wasmtime (EXPERIMENTAL)
AC_ARG_WITH([wasmtime], AS_HELP_STRING([--with-wasmtime], [build with wasmtime support]))
AS_IF([test "x$with_wasmtime" = "xyes"], AC_CHECK_HEADERS([wasmtime.h], AC_DEFINE([HAVE_WASMTIME], 1, [Define if wasmtime is available]), [AC_MSG_ERROR([*** Missing wasmtime headers])]))

dnl include support for wasmedge (EXPERIMENTAL)
AC_ARG_WITH([wasmedge], AS_HELP_STRING([--with-wasmedge], [build with WasmEdge support]))
AS_IF([test "x$with_wasmedge" = "xyes"], AC_CHECK_HEADERS([wasmedge/wasmedge.h], AC_DEFINE([HAVE_WASMEDGE], 1, [Define if WasmEdge is available]), [AC_MSG_ERROR([*** Missing wasmedge headers])]))

dnl include support for libkrun (EXPERIMENTAL)
AC_ARG_WITH([libkrun], AS_HELP_STRING([--with-libkrun], [build with libkrun support]))
AS_IF([test "x$with_libkrun" = "xyes"], AC_CHECK_HEADERS([libkrun.h], AC_DEFINE([HAVE_LIBKRUN], 1, [Define if libkrun is available]), [AC_MSG_ERROR([*** Missing libkrun headers])]))

AM_CONDITIONAL([ENABLE_KRUN], [test "x$with_libkrun" = xyes])

AM_CONDITIONAL([ENABLE_WASM], [test "x$with_wasmer" = xyes || test "x$with_wasmedge" = xyes || test "x$with_wasmtime" = xyes])

dnl include support for spin (EXPERIMENTAL)
AC_ARG_WITH([spin], AS_HELP_STRING([--with-spin], [build with spin support]))
AS_IF([test "x$with_spin" = "xyes"], AC_DEFINE([HAVE_SPIN], 1, [Define if spin is available]))


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
		AC_CHECK_FUNCS(sd_notify_barrier)
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
				#include <unistd.h>
				#include <stdint.h>
				#include <linux/bpf.h>
				void foo() {
					uint64_t val = 0x123456789;
					__attribute__ ((unused)) union bpf_attr attr;
					attr.insns = val;
				}
				int program = BPF_PROG_TYPE_CGROUP_DEVICE;
			]])],
			[AC_MSG_RESULT(yes)
			 AC_DEFINE([HAVE_EBPF], 1, [Define if eBPF is available])],
			[AC_MSG_RESULT(no)])
	])
])

use_fPIC=no
libcrun_public='__attribute__((visibility("default"))) extern'
if test "x$enable_shared" = "xyes"; then
        AC_DEFINE([SHARED_LIBCRUN], 1, [Define if shared libraries are enabled])
        AC_SUBST([SHARED_LIBCRUN])
        use_fPIC=yes
        if test "x$dynload_libcrun" = "xyes"; then
            libcrun_public='__attribute__((visibility("default"))) __attribute__((weak)) extern'
            AC_DEFINE([DYNLOAD_LIBCRUN], 1, [Define if shared libraries are enabled])
            AC_SUBST([DYNLOAD_LIBCRUN])
        else
            libcrun_public='__attribute__((visibility("default"))) extern'
        fi
fi

AC_DEFINE_UNQUOTED([LIBCRUN_PUBLIC], [$libcrun_public], [LIBCRUN_PUBLIC])

AC_ARG_WITH([python-bindings], AS_HELP_STRING([--with-python-bindings], [build the Python bindings]))
AS_IF([test "x$with_python_bindings" = "xyes"], [
	PKG_CHECK_MODULES([PYTHON], [python3], [], [AC_MSG_ERROR([*** python headers not found])])
        use_fPIC=yes
])

AC_ARG_WITH([lua-bindings], AS_HELP_STRING([--with-lua-bindings], [build the Lua bindings]))

AC_ARG_ENABLE(
	[lua-path-guessing],
	AS_HELP_STRING([--enable-lua-path-guessing], [guessing lua module path based on variables (default: yes), disable to use libdir as luaexecdir]),
[
case "${enableval}" in
	yes) enable_lua_path_guessing=true ;;
	no) enable_lua_path_guessing=false ;;
	*) AC_MSG_ERROR(bad value ${enablevaal} for --enable-lua-path-guessing) ;;
esac
],
[enable_lua_path_guessing=true]
)

AS_IF([test "x$with_lua_bindings" = "xyes"], [
	AX_PROG_LUA([5.4], [5.5], [], [AC_MSG_ERROR([*** lua interpreter not found])])
	AX_LUA_HEADERS([], [AC_MSG_ERROR([*** lua headers not found])])
	AX_LUA_LIBS([], [AC_MSG_ERROR([*** lua libs not found])])
	AS_IF([test "x$enable_lua_path_guessing" = "xfalse"], [
		AC_SUBST([luaexecdir], [$libdir])
	])
	use_fPIC=yes
])

AS_IF([test "x$use_fPIC" = "xyes"], [
	# configure should not touch CFLAGS/LDFLAGS but we need it to propagate it
	# to libocispec.
	export CFLAGS="$CFLAGS -fPIC"
	export LDFLAGS="$LDFLAGS -fPIC"
])

dnl criu
AC_ARG_ENABLE([criu], AS_HELP_STRING([--disable-criu], [Disable CRIU based checkpoint/restore support]))
AS_IF([test "x$enable_criu" != "xno"], [
	PKG_CHECK_MODULES([CRIU], [criu >= 3.15], [have_criu="yes"], [have_criu="no"
		AC_MSG_NOTICE([CRIU headers not found, building without CRIU support])])
	PKG_CHECK_MODULES([CRIU_JOIN_NS], [criu > 3.16], [have_criu_join_ns="yes"], [have_criu_join_ns="no"
	        AC_MSG_NOTICE([CRIU version doesn't support join-ns API])])
	PKG_CHECK_MODULES([CRIU_PRE_DUMP], [criu > 3.16.1], [have_criu_pre_dump="yes"], [have_criu_pre_dump="no"
	        AC_MSG_NOTICE([CRIU version doesn't support for pre-dumping])])
	PKG_CHECK_MODULES([CRIU_NETWORK_LOCK], [criu >= 3.19], [have_criu_network_lock="yes"], [have_criu_network_lock="no"
	        AC_MSG_NOTICE([CRIU version doesn't support network lock])])
	AS_IF([test "$have_criu" = "yes"], [
		AC_DEFINE([HAVE_CRIU], 1, [Define if CRIU is available])
	])
	AS_IF([test "$have_criu_join_ns" = "yes"], [
		AC_DEFINE([CRIU_JOIN_NS_SUPPORT], 1, [Define if CRIU join NS support is available])
	])
	AS_IF([test "$have_criu_pre_dump" = "yes"], [
		AC_DEFINE([CRIU_PRE_DUMP_SUPPORT], 1, [Define if CRIU pre-dump support is available])
	])
	AS_IF([test "$have_criu_network_lock" = "yes"], [
		AC_DEFINE([CRIU_NETWORK_LOCK], 1, [Define if CRIU network-lock support is available])
	])

], [AC_MSG_NOTICE([CRIU support disabled per user request])])

FOUND_LIBS=$LIBS
LIBS=""

AC_MSG_CHECKING([for new mount API (fsconfig)])
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([[
			#include <sys/mount.h>
			int cmd = FSCONFIG_CMD_CREATE;
	]])],
	[AC_MSG_RESULT(yes)
		 AC_DEFINE([HAVE_FSCONFIG_CMD_CREATE_SYS_MOUNT_H], 1, [Define if FSCONFIG_CMD_CREATE is available in sys/mount.h])],
	[AC_MSG_RESULT(no)])
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([[
			/* also make sure it doesn't conflict with <sys/mount.h> since it is always used.  */
			#include <sys/mount.h>
			#include <linux/mount.h>
			int cmd = FSCONFIG_CMD_CREATE;
	]])],
	[AC_MSG_RESULT(yes)
		 AC_DEFINE([HAVE_FSCONFIG_CMD_CREATE_LINUX_MOUNT_H], 1, [Define if FSCONFIG_CMD_CREATE is available in linux/mount.h])],
	[AC_MSG_RESULT(no)])

AC_MSG_CHECKING([for seccomp notify API])
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([[
			#include <linux/seccomp.h>
			int cmd = SECCOMP_GET_NOTIF_SIZES;
		]])],
		[AC_MSG_RESULT(yes)
		 AC_DEFINE([HAVE_SECCOMP_GET_NOTIF_SIZES], 1, [Define if SECCOMP_GET_NOTIF_SIZES is available])],
		[AC_MSG_RESULT(no)])

AC_SUBST([FOUND_LIBS])
AC_SUBST([CRUN_LDFLAGS])

AC_SUBST([CRUN_LIBDIR], [$libdir/crun])

[RPM_VERSION=$(echo $VERSION | sed -e's,^\([^-]*\).*$,\1,g')]

[GIT_COMMIT_ID=$(git rev-parse --short HEAD)]

AC_SUBST([RPM_VERSION])
AC_SUBST([GIT_COMMIT_ID])

AC_CHECK_TOOL(GPERF, gperf)
if test -z "$GPERF"; then
	AC_MSG_NOTICE(gperf not found - cannot rebuild signal parser code)
fi

AC_SEARCH_LIBS([argp_parse], [argp], [], [AC_MSG_ERROR([*** argp functions not found - install libargp or argp_standalone])])

AM_CONDITIONAL([PYTHON_BINDINGS], [test "x$with_python_bindings" = "xyes"])
AM_CONDITIONAL([LUA_BINDINGS], [test "x$with_lua_bindings" = "xyes"])
AM_CONDITIONAL([CRIU_SUPPORT], [test "x$have_criu" = "xyes"])
AM_CONDITIONAL([SHARED_LIBCRUN], [test "x$enable_shared" = "xyes"])

AC_CONFIG_FILES([Makefile])

AC_CONFIG_SUBDIRS([libocispec])
AC_OUTPUT
