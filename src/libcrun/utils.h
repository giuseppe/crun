/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef UTILS_H
# define UTILS_H
# include <config.h>
# include <stdio.h>
# include <stdlib.h>
# include <errno.h>
# include <argp.h>
# include "error.h"
# include <dirent.h>
# include <oci_runtime_spec.h>
# include "container.h"

# ifndef TEMP_FAILURE_RETRY
#  define TEMP_FAILURE_RETRY(expression)                                \
  (__extension__                                                        \
   ({ long int __result;                                                \
     do __result = (long int) (expression);                             \
     while (__result < 0 && errno == EINTR);                            \
     __result; }))
# endif


void cleanup_filep (FILE **f);
void cleanup_freep (void *p);
void cleanup_closep (void *p);
void cleanup_close_vecp (int **p);
void cleanup_dirp (DIR **p);
int close_and_reset (int *fd);

# define cleanup_file __attribute__((cleanup (cleanup_filep)))
# define cleanup_free __attribute__((cleanup (cleanup_freep)))
# define cleanup_close __attribute__((cleanup (cleanup_closep)))
# define cleanup_close_vec __attribute__((cleanup (cleanup_close_vecp)))
# define cleanup_dir __attribute__((cleanup (cleanup_dirp)))
# define arg_unused __attribute__((unused))

# define LIKELY(x) __builtin_expect((x),1)
# define UNLIKELY(x) __builtin_expect((x),0)

void *xmalloc (size_t size);

void *xrealloc (void *ptr, size_t size);

char *xstrdup (const char *str);

int xasprintf (char **str, const char *fmt, ...);

char *argp_mandatory_argument (char *arg, struct argp_state *state);

int crun_path_exists (const char *path, libcrun_error_t *err);

int write_file (const char *name, const void *data, size_t len, libcrun_error_t *err);

int write_file_at (int dirfd, const char *name, const void *data, size_t len, libcrun_error_t *err);

int crun_ensure_directory (const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_ensure_file (const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_ensure_directory_at (int dirfd, const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_ensure_file_at (int dirfd, const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_dir_p (const char *path, bool nofollow, libcrun_error_t *err);

int crun_dir_p_at (int dirfd, const char *path, bool nofollow, libcrun_error_t *err);

int detach_process ();

int create_file_if_missing_at (int dirfd, const char *file, libcrun_error_t *err);

int create_file_if_missing (const char *file, libcrun_error_t *err);

int check_running_in_user_namespace (libcrun_error_t *err);

int set_selinux_exec_label (const char *label, libcrun_error_t *err);

int add_selinux_mount_label (char **ret, const char *data, const char *label, libcrun_error_t *err);

int set_apparmor_profile (const char *profile, libcrun_error_t *err);

int read_all_fd (int fd, const char *description, char **out, size_t *len, libcrun_error_t *err);

int read_all_file (const char *path, char **out, size_t *len, libcrun_error_t *err);

int open_unix_domain_client_socket (const char *path, int dgram, libcrun_error_t *err);

int open_unix_domain_socket (const char *path, int dgram, libcrun_error_t *err);

int send_fd_to_socket (int server, int fd, libcrun_error_t *err);

int create_socket_pair (int *pair, libcrun_error_t *err);

int receive_fd_from_socket (int from, libcrun_error_t *err);

int create_signalfd (sigset_t *mask, libcrun_error_t *err);

int epoll_helper (int *fds, int *levelfds, libcrun_error_t *err);

int copy_from_fd_to_fd (int src, int dst, int consume, libcrun_error_t *err);

int run_process (char **args, libcrun_error_t *err);

size_t format_default_id_mapping (char **ret, uid_t container_id, uid_t host_id, int is_uid);

int run_process_with_stdin_timeout_envp (char *path, char **args, const char *cwd, int timeout, char **envp, char *stdin, size_t stdin_len, libcrun_error_t *err);

int close_fds_ge_than (int n, libcrun_error_t *err);

void get_current_timestamp (char *out);

int set_blocking_fd (int fd, int blocking, libcrun_error_t *err);

int parse_json_file (yajl_val *out, const char *jsondata, struct parser_context *ctx, libcrun_error_t *err);

int has_prefix (const char *str, const char *prefix);

const char *find_executable (const char *executable_path, const char *cwd);

int copy_recursive_fd_to_fd (int srcfd, int destfd, const char *srcname, const char *destname, libcrun_error_t *err);

int set_home_env (uid_t uid);

int libcrun_initialize_selinux (libcrun_error_t *err);

int libcrun_initialize_apparmor (libcrun_error_t *err);

#if !HAVE_SECURE_GETENV
char *secure_getenv (char const *name);
#endif

const char *find_annotation (libcrun_container_t *container, const char *name);

int get_file_type_at (int dirfd, mode_t *mode, bool nofollow, const char *path);

int get_file_type (mode_t *mode, bool nofollow, const char *path);

#endif
