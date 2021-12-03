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
#include "cgroup-cgroupfs.h"
#include "cgroup-internal.h"
#include "cgroup-systemd.h"
#include "cgroup-utils.h"
#include "cgroup-setup.h"
#include "cgroup-resources.h"
#include "ebpf.h"
#include "utils.h"
#include "status.h"
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

static int
libcrun_cgroup_enter_disabled (struct libcrun_cgroup_args *args arg_unused, struct libcrun_cgroup_status *out, libcrun_error_t *err arg_unused)
{
  out->path = NULL;
  return 0;
}

static int
libcrun_destroy_cgroup_disabled (struct libcrun_cgroup_status *cgroup_status arg_unused,
                                 libcrun_error_t *err arg_unused)
{
  return 0;
}

struct libcrun_cgroup_manager cgroup_manager_disabled =
  {
    .create_cgroup = libcrun_cgroup_enter_disabled,
    .destroy_cgroup = libcrun_destroy_cgroup_disabled,
  };

static int
get_cgroup_manager (int manager, struct libcrun_cgroup_manager **out, libcrun_error_t *err)
{
  switch (manager)
    {
    case CGROUP_MANAGER_DISABLED:
      *out = &cgroup_manager_disabled;
      return 0;

    case CGROUP_MANAGER_SYSTEMD:
      *out = &cgroup_manager_systemd;
      return 0;

    case CGROUP_MANAGER_CGROUPFS:
      *out = &cgroup_manager_cgroupfs;
      return 0;
    }

  *out = NULL;
  return crun_make_error (err, EINVAL, "unknown cgroup manager specified %d", manager);
}

const char *
find_delegate_cgroup (json_map_string_string *annotations)
{
  const char *annotation;

  annotation = find_annotation_map (annotations, "run.oci.delegate-cgroup");
  if (annotation)
    {
      if (annotation[0] == '\0')
        return NULL;
      return annotation;
    }

  return NULL;
}

static inline void
cleanup_sig_contp (void *p)
{
  pid_t *pp = p;
  if (*pp < 0)
    return;

  TEMP_FAILURE_RETRY (kill (*pp, SIGCONT));
}

static bool
must_stop_proc (runtime_spec_schema_config_linux_resources *resources)
{
  size_t i;

  if (resources == NULL)
    return false;

  if (resources->cpu && (resources->cpu->cpus || resources->cpu->mems))
    return true;

  if (resources->unified)
    {
      for (i = 0; i < resources->unified->len; i++)
        if (has_prefix (resources->unified->keys[i], "cpuset."))
          return true;
    }

  return false;
}

int
libcrun_cgroup_pause_unpause (struct libcrun_cgroup_status *status, const bool pause, libcrun_error_t *err)
{
  return libcrun_cgroup_pause_unpause_path (status->path, pause, err);
}

int
libcrun_cgroup_is_container_paused (struct libcrun_cgroup_status *status, bool *paused, libcrun_error_t *err)
{
  const char *cgroup_path = status->path;
  cleanup_free char *content = NULL;
  cleanup_free char *path = NULL;
  const char *state;
  int cgroup_mode;
  int ret;

  if (cgroup_path == NULL || cgroup_path[0] == '\0')
    return 0;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      state = "1";

      ret = append_paths (&path, err, CGROUP_ROOT, cgroup_path, "cgroup.freeze", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      state = "FROZEN";

      ret = append_paths (&path, err, CGROUP_ROOT "/freezer", cgroup_path, "freezer.state", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = read_all_file (path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  *paused = strstr (content, state) != NULL;
  return 0;
}

int
libcrun_cgroup_read_pids (struct libcrun_cgroup_status *status, bool recurse, pid_t **pids, libcrun_error_t *err)
{
  return libcrun_cgroup_read_pids_from_path (status->path, recurse, pids, err);
}

int
libcrun_cgroup_killall (struct libcrun_cgroup_status *cgroup_status, int signal, libcrun_error_t *err)
{
  return cgroup_killall_path (cgroup_status->path, signal, err);
}

int
libcrun_cgroup_destroy (struct libcrun_cgroup_status *cgroup_status, libcrun_error_t *err)
{
  struct libcrun_cgroup_manager *cgroup_manager;
  int ret;


  ret = get_cgroup_manager (cgroup_status->manager, &cgroup_manager, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = cgroup_manager->destroy_cgroup (cgroup_status, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  return 0;
}

int
libcrun_update_cgroup_resources (struct libcrun_cgroup_status *status,
                                 runtime_spec_schema_config_linux_resources *resources,
                                 libcrun_error_t *err)
{
  return update_cgroup_resources (status->path, resources, err);
}

int
libcrun_cgroup_enter (struct libcrun_cgroup_args *args, struct libcrun_cgroup_status **out, libcrun_error_t *err)
{
  __attribute__ ((unused)) pid_t sigcont_cleanup __attribute__ ((cleanup (cleanup_sig_contp))) = -1;
  cleanup_cgroup_status struct libcrun_cgroup_status *status;
  struct libcrun_cgroup_manager *cgroup_manager;
  int manager = args->manager;
  uid_t root_uid = args->root_uid;
  uid_t root_gid = args->root_gid;
  libcrun_error_t tmp_err = NULL;
  bool cgroup_path_empty;
  int cgroup_mode;
  int rootless;
  int ret;

  status = xmalloc0 (sizeof *status);

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  /* If the cgroup configuration is limiting what CPUs/memory Nodes are available for the container,
     then stop the container process during the cgroup configuration to avoid it being rescheduled on
     a CPU that is not allowed.  This extra step is required for setting up the sub cgroup with the
     systemd driver.  The alternative would be to temporarily setup the cpus/mems using d-bus.
  */
  if (must_stop_proc (args->resources))
    {
      ret = TEMP_FAILURE_RETRY (kill (args->pid, SIGSTOP));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "cannot stop container process '%d' with SIGSTOP", args->pid);

      /* Send SIGCONT as soon as the function exits.  */
      sigcont_cleanup = args->pid;
    }

  if (cgroup_mode == CGROUP_MODE_HYBRID)
    {
      /* We don't really support hybrid mode, so check that cgroups2 is not using any controller.  */

      size_t len;
      cleanup_free char *buffer = NULL;

      ret = read_all_file (CGROUP_ROOT "/unified/cgroup.controllers", &buffer, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (len > 0)
        return crun_make_error (err, 0, "cgroups in hybrid mode not supported, drop all controllers from cgroupv2");
    }

  ret = get_cgroup_manager (manager, &cgroup_manager, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = cgroup_manager->create_cgroup (args, status, err);

  if (LIKELY (ret >= 0))
    {
      bool need_chown = root_uid != (uid_t) -1 || root_gid != (gid_t) -1;

      if (status->path == NULL)
        return crun_make_error (err, 0, "internal error: cgroup path not set");

      if (cgroup_mode == CGROUP_MODE_UNIFIED && need_chown)
        {
          ret = chown_cgroups (status->path, root_uid, root_gid, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (args->resources)
        {
          ret = update_cgroup_resources (status->path, args->resources, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      goto success;
    }

  rootless = is_rootless (&tmp_err);
  if (UNLIKELY (rootless < 0))
    {
      crun_error_release (err);
      *err = tmp_err;
      return rootless;
    }

  /* Ignore errors only if there is no explicit path set in the configuration.  */
  cgroup_path_empty = (args->cgroup_path == NULL || args->cgroup_path[0] == '\0');
  if (rootless > 0 && cgroup_path_empty && (cgroup_mode != CGROUP_MODE_UNIFIED || manager != CGROUP_MANAGER_SYSTEMD))
    {
      /* Ignore cgroups errors and set there is no cgroup path to use.  */
      free (status->path);
      status->path = NULL;
      crun_error_release (err);
      return 0;
    }

  if (ret < 0)
    return ret;

success:
  *out = status;
  status = NULL;
  return 0;
}

int
libcrun_cgroup_has_oom (struct libcrun_cgroup_status *status, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  const char *path = NULL;
  const char *prefix = NULL;
  size_t content_size = 0;
  int cgroup_mode;
  char *it;

  path = status->path;
  if (UNLIKELY (path == NULL || path[0] == '\0'))
    return 0;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (path == NULL || path[0] == '\0')
    return 0;

  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      {
        cleanup_free char *events_path = NULL;
        int ret;

        ret = append_paths (&events_path, err, CGROUP_ROOT, path, "memory.events", NULL);
        if (UNLIKELY (ret < 0))
          return ret;

        /* read_all_file always NUL terminates the output.  */
        ret = read_all_file (events_path, &content, &content_size, err);
        if (UNLIKELY (ret < 0))
          return ret;

        prefix = "oom ";
        break;
      }
    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      {
        cleanup_free char *oom_control_path = NULL;
        int ret;

        ret = append_paths (&oom_control_path, err, CGROUP_ROOT, "memory", path, "memory.oom_control", NULL);
        if (UNLIKELY (ret < 0))
          return ret;

        /* read_all_file always NUL terminates the output.  */
        ret = read_all_file (oom_control_path, &content, &content_size, err);
        if (UNLIKELY (ret < 0))
          return ret;

        prefix = "oom_kill ";
        break;
      }

    default:
      return crun_make_error (err, 0, "invalid cgroup mode %d", cgroup_mode);
    }

  it = content;
  while (it && *it)
    {
      if (has_prefix (it, prefix))
        {
          it += strlen (prefix);
          while (*it == ' ')
            it++;

          return *it != '0';
        }
      else
        {
          it = strchr (it, '\n');
          if (it == NULL)
            return 0;
          it++;
        }
    }

  return 0;
}

int
libcrun_cgroup_get_status (struct libcrun_cgroup_status *cgroup_status,
                           libcrun_container_status_t *status,
                           libcrun_error_t *err arg_unused)
{
  status->cgroup_path = cgroup_status->path;
  status->scope = cgroup_status->scope;
  return 0;
}

void
libcrun_cgroup_status_free (struct libcrun_cgroup_status *cgroup_status)
{
  if (cgroup_status == NULL)
    return;

  free (cgroup_status->path);
  free (cgroup_status->scope);
  free (cgroup_status);
}

struct libcrun_cgroup_status *
libcrun_cgroup_make_status (libcrun_container_status_t *status)
{
  struct libcrun_cgroup_status *ret;

  ret = xmalloc0 (sizeof *ret);

  if (status->cgroup_path)
    ret->path = xstrdup (status->cgroup_path);

  if (status->scope)
    ret->scope = xstrdup (status->scope);

  if (is_empty_string (status->cgroup_path) && is_empty_string (status->scope))
    ret->manager = CGROUP_MANAGER_DISABLED;
  else
    ret->manager = status->systemd_cgroup ? CGROUP_MANAGER_SYSTEMD : CGROUP_MANAGER_CGROUPFS;

  return ret;
}
