/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
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
#ifndef CGROUP_H
#define CGROUP_H

#include "container.h"
#include <unistd.h>

#ifndef CGROUP_ROOT
#  define CGROUP_ROOT "/sys/fs/cgroup"
#endif

enum
{
  CGROUP_MODE_UNIFIED = 1,
  CGROUP_MODE_LEGACY,
  CGROUP_MODE_HYBRID
};

enum
{
  CGROUP_MANAGER_CGROUPFS = 1,
  CGROUP_MANAGER_SYSTEMD,
  CGROUP_MANAGER_DISABLED
};

struct libcrun_cgroup_status;

struct libcrun_cgroup_args
{
  runtime_spec_schema_config_linux_resources *resources;
  json_map_string_string *annotations;
  const char *cgroup_path;
  int manager;
  pid_t pid;
  uid_t root_uid;
  gid_t root_gid;
  const char *id;
};

/* cgroup life-cycle management.  */
int libcrun_cgroup_enter (struct libcrun_cgroup_args *args, struct libcrun_cgroup_status **out, libcrun_error_t *err);
int libcrun_cgroup_destroy (int manager, struct libcrun_cgroup_status *cgroup_status, libcrun_error_t *err);

/* Handle the cgroup status.  */
int libcrun_cgroup_get_status (struct libcrun_cgroup_status *cgroup_status, libcrun_container_status_t *status,
                               libcrun_error_t *err);
void libcrun_cgroup_status_free (struct libcrun_cgroup_status *cgroup_status);

struct libcrun_cgroup_status *libcrun_cgroup_make_status (libcrun_container_status_t *status);

static inline void
cgroup_status_freep (struct libcrun_cgroup_status **p)
{
  struct libcrun_cgroup_status *s = *p;
  if (s)
    libcrun_cgroup_status_free (s);
}
#define cleanup_cgroup_status __attribute__ ((cleanup (cgroup_status_freep)))

/* Operations on the cgroup.  */

int libcrun_cgroup_killall (struct libcrun_cgroup_status *cgroup_status, int signal, libcrun_error_t *err);

int libcrun_cgroup_has_oom (struct libcrun_cgroup_status *status, libcrun_error_t *err);

int libcrun_cgroup_read_pids (struct libcrun_cgroup_status *status, bool recurse, pid_t **pids, libcrun_error_t *err);

int libcrun_update_cgroup_resources (struct libcrun_cgroup_status *status,
                                     runtime_spec_schema_config_linux_resources *resources,
                                     libcrun_error_t *err);

int libcrun_cgroup_is_container_paused (struct libcrun_cgroup_status *status, bool *paused, libcrun_error_t *err);

int libcrun_cgroup_pause_unpause (struct libcrun_cgroup_status *status, const bool pause, libcrun_error_t *err);

/* Random utilities not bound to cgroup life-cycle.  */

int libcrun_move_process_to_cgroup (pid_t pid, pid_t init_pid, char *path, libcrun_error_t *err);

int libcrun_cgroups_create_symlinks (int dirfd, libcrun_error_t *err);

int libcrun_get_current_unified_cgroup (char **path, libcrun_error_t *err);

int libcrun_get_cgroup_mode (libcrun_error_t *err);

int libcrun_cgroup_read_pids_from_path (const char *path, bool recurse, pid_t **pids, libcrun_error_t *err);

#endif
