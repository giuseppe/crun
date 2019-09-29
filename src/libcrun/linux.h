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
#ifndef LINUX_H
# define LINUX_H
# include <config.h>
# include <stdio.h>
# include <stdlib.h>
# include "error.h"
# include <errno.h>
# include <argp.h>
# include <oci_runtime_spec.h>
# include "container.h"
# include "status.h"

typedef int (*container_entrypoint_t) (void *args, const char *notify_socket,
                                       int sync_socket,
                                       libcrun_error_t *err);

pid_t libcrun_run_linux_container (libcrun_container_t *container,
                                   int detach,
                                   container_entrypoint_t entrypoint,
                                   void *args,
                                   int *sync_socket_out,
                                   libcrun_error_t *err);
int get_notify_fd (libcrun_context_t *context, libcrun_container_t *container, int *notify_socket_out, libcrun_error_t *err);
int libcrun_set_mounts (libcrun_container_t *container, const char *rootfs, libcrun_error_t *err);
int libcrun_do_pivot_root (libcrun_container_t *container, bool no_pivot, const char *rootfs, libcrun_error_t *err);
int libcrun_set_usernamespace (libcrun_container_t *container, pid_t pid, libcrun_error_t *err);
int libcrun_set_caps (oci_container_process_capabilities *capabilities, uid_t uid, gid_t gid, int no_new_privileges, libcrun_error_t *err);
int libcrun_set_rlimits (oci_container_process_rlimits_element **rlimits, size_t len, libcrun_error_t *err);
int libcrun_set_selinux_exec_label (oci_container_process *proc, libcrun_error_t *err);
int libcrun_set_apparmor_profile (oci_container_process *proc, libcrun_error_t *err);
int libcrun_set_hostname (libcrun_container_t *container, libcrun_error_t *err);
int libcrun_set_oom (libcrun_container_t *container, libcrun_error_t *err);
int libcrun_set_sysctl (libcrun_container_t *container, libcrun_error_t *err);
int libcrun_set_terminal (libcrun_container_t *container, libcrun_error_t *err);
int libcrun_join_process (libcrun_container_t *container, pid_t pid_to_join, libcrun_container_status_t *status, int detach, int *terminal_fd, libcrun_error_t *err);
int libcrun_linux_container_update (libcrun_container_status_t *status, const char *content, size_t len, libcrun_error_t *err);
int libcrun_create_keyring (const char *name, libcrun_error_t *err);
int libcrun_container_pause_linux (libcrun_container_status_t *status, libcrun_error_t *err);
int libcrun_container_unpause_linux (libcrun_container_status_t *status, libcrun_error_t *err);
int libcrun_container_enter_cgroup_ns (libcrun_container_t *container, libcrun_error_t *err);

#endif
