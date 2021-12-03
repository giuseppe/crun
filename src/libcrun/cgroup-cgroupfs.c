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

#define _GNU_SOURCE

#include <config.h>
#include "cgroup.h"
#include "cgroup-internal.h"
#include "cgroup-systemd.h"
#include "cgroup-setup.h"
#include "cgroup-utils.h"
#include "cgroup-cgroupfs.h"
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/vfs.h>
#include <inttypes.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>

int
libcrun_cgroup_enter_cgroupfs (struct libcrun_cgroup_args *args, struct libcrun_cgroup_status *out, libcrun_error_t *err)
{
  cleanup_free char *target_cgroup_cleanup = NULL;
  const char *cgroup_path = args->cgroup_path;
  const char *process_target_cgroup = NULL;
  const char *delegate_cgroup;
  const char *id = args->id;
  pid_t pid = args->pid;
  int cgroup_mode;
  int ret;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  delegate_cgroup = find_delegate_cgroup (args->annotations);

  if (cgroup_mode != CGROUP_MODE_UNIFIED && delegate_cgroup)
    return crun_make_error (err, 0, "delegate-cgroup not supported on cgroup v1");

  if (cgroup_path == NULL)
    xasprintf (&(out->path), "/%s", id);
  else
    {
      if (cgroup_path[0] == '/')
        out->path = xstrdup (cgroup_path);
      else
        xasprintf (&(out->path), "/%s", cgroup_path);
    }

  if (delegate_cgroup == NULL)
    process_target_cgroup = out->path;
  else
    {
      ret = append_paths (&target_cgroup_cleanup, err, out->path, delegate_cgroup, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      process_target_cgroup = target_cgroup_cleanup;
    }

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      int ret;

      ret = enable_controllers (process_target_cgroup, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return enter_cgroup (cgroup_mode, pid, 0, process_target_cgroup, true, err);
}

int
libcrun_destroy_cgroup_cgroupfs (struct libcrun_cgroup_status *cgroup_status,
                                 libcrun_error_t *err)
{
  int mode;
  int ret;

  mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (mode < 0))
    return mode;

  ret = cgroup_killall_path (cgroup_status->path, SIGKILL, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  ret = destroy_cgroup_path (cgroup_status->path, mode, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  return 0;
}
