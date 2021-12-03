DIST_SUBDIRS = libocispec
SUBDIRS = libocispec
ACLOCAL_AMFLAGS = -I m4

WD := $(shell pwd)

rpm: dist-gzip rpm/crun.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-gzip
	rpmbuild -ba --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" rpm/crun.spec

srpm: dist-gzip rpm/crun.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-gzip
	rpmbuild -bs --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" rpm/crun.spec

CLEANFILES = crun.spec

lib_LTLIBRARIES = libcrun.la

check_LIBRARIES = libcrun_testing.a

libcrun_SOURCES = src/libcrun/utils.c \
			src/libcrun/cloned_binary.c \
			src/libcrun/container.c \
			src/libcrun/cgroup.c \
			src/libcrun/cgroup-resources.c \
			src/libcrun/cgroup-setup.c \
			src/libcrun/cgroup-systemd.c \
			src/libcrun/cgroup-utils.c \
			src/libcrun/criu.c \
			src/libcrun/linux.c \
			src/libcrun/seccomp.c \
			src/libcrun/ebpf.c \
			src/libcrun/error.c \
			src/libcrun/status.c \
			src/libcrun/terminal.c \
			src/libcrun/chroot_realpath.c \
			src/libcrun/signals.c \
			src/libcrun/mount_flags.c \
			src/libcrun/seccomp_notify.c

if HAVE_EMBEDDED_YAJL
maybe_libyajl.la = libocispec/yajl/libyajl.la
else
maybe_libyajl.la =
endif

libocispec/libocispec.la:
	$(MAKE) $(AM_MAKEFLAGS) -C libocispec libocispec.la

libcrun_la_SOURCES = $(libcrun_SOURCES)
libcrun_la_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -fvisibility=hidden
libcrun_la_LIBADD = libocispec/libocispec.la $(FOUND_LIBS) $(maybe_libyajl.la)
libcrun_la_LDFLAGS = -Wl,--version-script=$(abs_top_srcdir)/libcrun.lds

# build a version with all the symbols visible for testing
libcrun_testing_a_SOURCES = $(libcrun_SOURCES)
libcrun_testing_a_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -fvisibility=default
libcrun_testing_a_LIBADD = libocispec/libocispec.la $(maybe_libyajl.la)

if PYTHON_BINDINGS
pyexec_LTLIBRARIES = python_crun.la
python_crun_la_SOURCES = python/crun_python.c
python_crun_la_CFLAGS = -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/libocispec/src -I $(abs_top_builddir)/src $(PYTHON_CFLAGS)
python_crun_la_LDFLAGS = -avoid-version -module $(PYTHON_LDFLAGS)
python_crun_la_LIBADD = libcrun.la $(PYTHON_LIBS) $(FOUND_LIBS) $(maybe_libyajl.la)
endif

crun_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src
crun_SOURCES = src/crun.c src/run.c src/delete.c src/kill.c src/pause.c src/unpause.c src/spec.c \
		src/exec.c src/list.c src/create.c src/start.c src/state.c src/update.c src/ps.c \
		src/checkpoint.c src/restore.c
crun_LDADD = libcrun.la $(FOUND_LIBS) $(maybe_libyajl.la)
crun_LDFLAGS = $(CRUN_LDFLAGS)

EXTRA_DIST = COPYING COPYING.libcrun README.md NEWS SECURITY.md rpm/crun.spec.in autogen.sh \
	src/crun.h src/list.h src/run.h src/delete.h src/kill.h src/pause.h src/unpause.h \
	src/create.h src/start.h src/state.h src/exec.h src/spec.h src/update.h src/ps.h \
	src/checkpoint.h src/restore.h src/libcrun/seccomp_notify.h src/libcrun/seccomp_notify_plugin.h \
	src/libcrun/container.h src/libcrun/seccomp.h src/libcrun/ebpf.h \
	src/libcrun/cgroup.h src/libcrun/cgroup-internal.h \
	src/libcrun/cgroup-resources.h src/libcrun/cgroup-setup.h \
	src/libcrun/cgroup-systemd.h src/libcrun/cgroup-utils.h \
	src/libcrun/linux.h src/libcrun/utils.h src/libcrun/error.h src/libcrun/criu.h \
	src/libcrun/status.h src/libcrun/terminal.h src/libcrun/mount_flags.h \
	src/libcrun/intprops.h crun.1.md crun.1 libcrun.lds

UNIT_TESTS = tests/tests_libcrun_utils tests/tests_libcrun_errors

bin_PROGRAMS = crun
noinst_PROGRAMS = tests/init $(UNIT_TESTS) tests/tests_libcrun_fuzzer

TESTS_LDADD = libcrun_testing.a $(FOUND_LIBS) $(maybe_libyajl.la)

tests_init_LDADD =
tests_init_LDFLAGS = -static-libgcc -all-static
tests_init_SOURCES = tests/init.c

tests_tests_libcrun_utils_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src -I $(abs_top_srcdir)/src
tests_tests_libcrun_utils_SOURCES = tests/tests_libcrun_utils.c
tests_tests_libcrun_utils_LDADD = $(TESTS_LDADD)
tests_tests_libcrun_utils_LDFLAGS = $(crun_LDFLAGS)

tests_tests_libcrun_fuzzer_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src -I $(abs_top_srcdir)/src
tests_tests_libcrun_fuzzer_SOURCES = tests/tests_libcrun_fuzzer.c
tests_tests_libcrun_fuzzer_LDADD = $(TESTS_LDADD) libocispec/libocispec.la $(maybe_libyajl.la)
tests_tests_libcrun_fuzzer_LDFLAGS = $(crun_LDFLAGS)

tests_tests_libcrun_errors_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src -I $(abs_top_srcdir)/src
tests_tests_libcrun_errors_SOURCES = tests/tests_libcrun_errors.c
tests_tests_libcrun_errors_LDADD = $(TESTS_LDADD)
tests_tests_libcrun_errors_LDFLAGS = $(crun_LDFLAGS)

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)
PY_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh

TESTS = tests/test_capabilities.py \
	tests/test_cwd.py \
	tests/test_checkpoint_restore.py \
	tests/test_devices.py \
	tests/test_hostname.py \
	tests/test_limits.py \
	tests/test_mounts.py \
	tests/test_paths.py \
	tests/test_pid.py \
	tests/test_pid_file.py \
	tests/test_preserve_fds.py \
	tests/test_uid_gid.py \
	tests/test_rlimits.py \
	tests/test_tty.py \
	tests/test_hooks.py \
	tests/test_update.py \
	tests/test_detach.py \
	tests/test_resources.py \
	tests/test_start.py \
	tests/test_exec.py \
	tests/test_seccomp.py \
	$(UNIT_TESTS)

.version:
	$(AM_V_GEN)echo $(VERSION) > $@-t && mv $@-t $@

git-version.h:
	@if test -e $(abs_top_srcdir)/.git; then \
		$(AM__GEN)printf "/* autogenerated.  */\n#ifndef GIT_VERSION\n# define GIT_VERSION \"%s\"\n#endif\n" $(shell git --git-dir=$(abs_top_srcdir)/.git rev-parse HEAD) > $@-t && mv $@-t $@; \
	fi

nixpkgs:
	@nix run -f channel:nixpkgs-unstable nix-prefetch-git -c nix-prefetch-git \
		--no-deepClone https://github.com/nixos/nixpkgs > nix/nixpkgs.json

dist-hook:
	$(AM_V_GEN)echo $(VERSION) > $(distdir)/.tarball-version
	$(AM__GEN)cp git-version.h $(distdir)/git-version.h

EXTRA_DIST += $(TESTS) tests/Makefile.tests tests/run_all_tests.sh tests/tests_utils.py build-aux/git-version-gen .version git-version.h src/libcrun/signals.perf src/libcrun/mount_flags.perf
BUILT_SOURCES = .version git-version.h

man1_MANS = crun.1

crun.1: $(abs_srcdir)/crun.1.md
if HAVE_MD2MAN
	$(MD2MAN) -in $(abs_srcdir)/crun.1.md -out crun.1
endif HAVE_MD2MAN

generate-man: crun.1

sync:
	(cd libocispec; git pull https://github.com/containers/libocispec main)

coverity:
	$(MAKE) $(AM_MAKEFLAGS) -C libocispec
	$(MAKE) $(AM_MAKEFLAGS) crun

libcrun.rs: src/libcrun/container.h
	bindgen src/libcrun/container.h -- -I$(abs_builddir) -I$(abs_builddir)/libocispec/src  > $@

generate-rust-bindings: libcrun.rs

generate-signals.c: src/libcrun/signals.perf
	${GPERF} --lookup-function-name libcrun_signal_in_word_set -m 100 --null-strings --pic -tCEG -S1 $< > src/libcrun/signals.c

generate-mount_flags.c: src/libcrun/mount_flags.perf
	${GPERF} --lookup-function-name libcrun_mount_flag_in_word_set -m 100 -tCEG -S1 $< > src/libcrun/mount_flags.c

clang-format:
# do not format files that were copied into the source directory.
	git ls-files src tests | egrep "\\.[hc]" | grep -v "chroot_realpath.c\|cloned_binary.c\|signals.c\|mount_flags.c" | xargs clang-format -style=file -i

.PHONY: coverity sync generate-rust-bindings generate-signals.c generate-mount_flags.c clang-format
