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
#include "cgroup-utils.h"
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
initialize_cpuset_subsystem_rec (char *path, size_t path_len, char *cpus, char *mems, libcrun_error_t *err)
{
  cleanup_close int dirfd = -1;
  cleanup_close int mems_fd = -1;
  cleanup_close int cpus_fd = -1;
  int b_len;

  dirfd = open (path, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", path);

  if (cpus[0] == '\0')
    {
      cpus_fd = openat (dirfd, "cpuset.cpus", O_RDWR);
      if (UNLIKELY (cpus_fd < 0))
        return crun_make_error (err, errno, "open '%s/%s'", path, "cpuset.cpus");

      b_len = TEMP_FAILURE_RETRY (read (cpus_fd, cpus, 256));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "read from 'cpuset.cpus'");
      cpus[b_len] = '\0';
      if (cpus[0] == '\n')
        cpus[0] = '\0';
    }

  if (mems[0] == '\0')
    {
      mems_fd = openat (dirfd, "cpuset.mems", O_RDWR);
      if (UNLIKELY (mems_fd < 0))
        return crun_make_error (err, errno, "open '%s/%s'", path, "cpuset.mems");

      b_len = TEMP_FAILURE_RETRY (read (mems_fd, mems, 256));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "read from 'cpuset.mems'");
      mems[b_len] = '\0';
      if (mems[0] == '\n')
        mems[0] = '\0';
    }

  /* look up in the parent directory.  */
  if (cpus[0] == '\0' || mems[0] == '\0')
    {
      size_t parent_path_len;
      int ret;

      for (parent_path_len = path_len - 1; parent_path_len > 1 && path[parent_path_len] != '/'; parent_path_len--)
        ;
      if (parent_path_len == 1)
        return 0;

      path[parent_path_len] = '\0';
      ret = initialize_cpuset_subsystem_rec (path, parent_path_len, cpus, mems, err);
      path[parent_path_len] = '/';
      if (UNLIKELY (ret < 0))
        {
          /* Ignore errors here and try to write the configuration we want later on.  */
          crun_error_release (err);
        }
    }

  if (cpus_fd >= 0)
    {
      b_len = TEMP_FAILURE_RETRY (write (cpus_fd, cpus, strlen (cpus)));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "write 'cpuset.cpus'");
    }

  if (mems_fd >= 0)
    {
      b_len = TEMP_FAILURE_RETRY (write (mems_fd, mems, strlen (mems)));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "write 'cpuset.mems'");
    }

  return 0;
}

static int
initialize_cpuset_subsystem (const char *path, libcrun_error_t *err)
{
  cleanup_free char *tmp_path = xstrdup (path);
  char cpus_buf[257];
  char mems_buf[257];

  cpus_buf[0] = mems_buf[0] = '\0';
  return initialize_cpuset_subsystem_rec (tmp_path, strlen (tmp_path), cpus_buf, mems_buf, err);
}

static int
initialize_memory_subsystem (const char *path, libcrun_error_t *err)
{
  const char *const files[]
      = { "memory.limit_in_bytes", "memory.kmem.limit_in_bytes", "memory.memsw.limit_in_bytes", NULL };
  cleanup_close int dirfd = -1;
  int i;

  dirfd = open (path, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", path);

  for (i = 0; files[i]; i++)
    {
      int ret;

      ret = write_file_at (dirfd, files[i], "-1", 2, err);
      if (UNLIKELY (ret < 0))
        {
          /* Ignore any error here.  */
          crun_error_release (err);
        }
    }

  return 0;
}

int
enter_cgroup_subsystem (pid_t pid, const char *subsystem, const char *path, bool create_if_missing,
                        libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  int ret;

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, subsystem ? subsystem : "", path ? path : "", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  if (create_if_missing)
    {
      ret = crun_ensure_directory (cgroup_path, 0755, false, err);
      if (UNLIKELY (ret < 0))
        {
          if (errno != EROFS)
            return crun_make_error (err, errno, "creating cgroup directory `%s`", cgroup_path);

          crun_error_release (err);
          return 0;
        }

      if (strcmp (subsystem, "cpuset") == 0)
        {
          ret = initialize_cpuset_subsystem (cgroup_path, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      if (strcmp (subsystem, "memory") == 0)
        {
          ret = initialize_memory_subsystem (cgroup_path, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  else
    {
      ret = crun_path_exists (cgroup_path, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 0)
        return 0;
    }

  return move_process_to_cgroup (pid, subsystem, path, err);
}

static int
get_file_owner (const char *path, uid_t *uid, gid_t *gid)
{
  struct stat st;
  int ret;

#ifdef HAVE_STATX
  struct statx stx;

  ret = statx (AT_FDCWD, path, AT_STATX_DONT_SYNC, STATX_UID | STATX_GID, &stx);
  if (UNLIKELY (ret < 0))
    {
      if (errno == ENOSYS || errno == EINVAL)
        goto fallback;

      return ret;
    }
  *uid = stx.stx_uid;
  *gid = stx.stx_gid;
  return ret;

fallback:
#endif
  ret = stat (path, &st);
  if (UNLIKELY (ret < 0))
    return ret;

  *uid = st.st_uid;
  *gid = st.st_gid;
  return ret;
}

static int
copy_owner (const char *from, const char *to, libcrun_error_t *err)
{
  uid_t uid = 0;
  gid_t gid = 0;
  int ret;

  ret = get_file_owner (from, &uid, &gid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot get file owner for %s", from);

  if (uid == 0 && gid == 0)
    return 0;

  return chown_cgroups (to, uid, gid, err);
}

static int
read_unified_cgroup_pid (pid_t pid, char **path, libcrun_error_t *err)
{
  int ret;
  char cgroup_path[32];
  char *from, *to;
  cleanup_free char *content = NULL;

  sprintf (cgroup_path, "/proc/%d/cgroup", pid);

  ret = read_all_file (cgroup_path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  from = strstr (content, "0::");
  if (UNLIKELY (from == NULL))
    return crun_make_error (err, -1, "cannot find cgroup2 for the process %d", pid);

  from += 3;
  to = strchr (from, '\n');
  to = strchr (from, '\n');
  if (UNLIKELY (to == NULL))
    return crun_make_error (err, -1, "cannot parse `%s`", cgroup_path);
  *to = '\0';

  *path = xstrdup (from);
  return 0;
}

static int
enter_cgroup_v1 (pid_t pid, const char *path, bool create_if_missing, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  bool entered_any = false;
  size_t content_size;
  char *controller;
  char pid_str[16];
  char *saveptr;
  bool has_data;
  int rootless;
  int ret;

  sprintf (pid_str, "%d", pid);

  rootless = is_rootless (err);
  if (UNLIKELY (rootless < 0))
    return rootless;

  ret = read_all_file ("/proc/self/cgroup", &content, &content_size, err);
  if (UNLIKELY (ret < 0))
    {
      if (crun_error_get_errno (err) == ENOENT)
        {
          crun_error_release (err);
          return 0;
        }
      return ret;
    }

  for (has_data = read_proc_cgroup (content, &saveptr, NULL, &controller, NULL);
       has_data;
       has_data = read_proc_cgroup (NULL, &saveptr, NULL, &controller, NULL))
    {
      char subsystem_path[64];
      char *subsystem;

      if (has_prefix (controller, "name="))
        controller += 5;

      subsystem = controller[0] == '\0' ? "unified" : controller;

      snprintf (subsystem_path, sizeof (subsystem_path), CGROUP_ROOT "/%s", subsystem);
      ret = crun_path_exists (subsystem_path, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 0)
        continue;

      entered_any = true;
      ret = enter_cgroup_subsystem (pid, subsystem, path, create_if_missing, err);
      if (UNLIKELY (ret < 0))
        {
          int errcode = crun_error_get_errno (err);
          if (rootless && (errcode == EACCES || errcode == EPERM))
            {
              crun_error_release (err);
              continue;
            }
          return ret;
        }
    }

  if (entered_any)
    return 0;

  return crun_make_error (err, 0, "could not join cgroup");
}

static int
enter_cgroup_v2 (pid_t pid, pid_t init_pid, const char *path, bool create_if_missing, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path_procs = NULL;
  cleanup_free char *cgroup_path = NULL;
  char pid_str[16];
  int repeat;
  int ret;

  sprintf (pid_str, "%d", pid);

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  if (create_if_missing)
    {
      ret = crun_ensure_directory (cgroup_path, 0755, false, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = append_paths (&cgroup_path_procs, err, cgroup_path, "cgroup.procs", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = write_file (cgroup_path_procs, pid_str, strlen (pid_str), err);
  if (LIKELY (ret >= 0))
    return ret;

  /* If the cgroup is not being created, try to handle EBUSY.  */
  if (create_if_missing || crun_error_get_errno (err) != EBUSY)
    return ret;

  crun_error_release (err);

  /* There are subdirectories so it is not possible to join the initial
     cgroup.  Create a subdirectory and use that.
     It can still fail if the container creates a subdirectory under
     /sys/fs/cgroup/../crun-exec/  */
  for (repeat = 0;; repeat++)
    {
      cleanup_free char *cgroup_crun_exec_path = NULL;
      cleanup_free char *cgroup_sub_path_procs = NULL;

      /* There is an init pid, try to join its cgroup.  */
      if (init_pid > 0)
        {
          ret = read_unified_cgroup_pid (init_pid, &cgroup_crun_exec_path, err);
          if (UNLIKELY (ret < 0))
            return ret;

          /* Make sure the cgroup is below the initial cgroup specified for the container.  */
          if (strncmp (path, cgroup_crun_exec_path, strlen (path)))
            {
              free (cgroup_crun_exec_path);
              cgroup_crun_exec_path = NULL;
            }
        }

      /* There is no init_pid to lookup, try a static path.  */
      if (cgroup_crun_exec_path == NULL)
        xasprintf (&cgroup_crun_exec_path, "%s/crun-exec", path);

      ret = append_paths (&cgroup_sub_path_procs, err, CGROUP_ROOT, cgroup_crun_exec_path, "cgroup.procs", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_file (cgroup_sub_path_procs, pid_str, strlen (pid_str), err);
      if (UNLIKELY (ret < 0))
        {
          /* The init process might have moved to a different cgroup, try again.  */
          if (crun_error_get_errno (err) == EBUSY && init_pid && repeat < 20)
            {
              crun_error_release (err);
              continue;
            }
          return ret;
        }
      return copy_owner (cgroup_path_procs, cgroup_crun_exec_path, err);
    }
  return ret;
}

int
enter_cgroup (int cgroup_mode, pid_t pid, pid_t init_pid, const char *path,
              bool create_if_missing, libcrun_error_t *err)
{
  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    return enter_cgroup_v2 (pid, init_pid, path, create_if_missing, err);

  return enter_cgroup_v1 (pid, path, create_if_missing, err);
}
