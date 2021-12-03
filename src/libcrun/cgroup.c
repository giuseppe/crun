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

enum
{
  CGROUP_MEMORY = 1 << 0,
  CGROUP_CPU = 1 << 1,
  CGROUP_HUGETLB = 1 << 2,
  CGROUP_CPUSET = 1 << 3,
  CGROUP_PIDS = 1 << 4,
  CGROUP_IO = 1 << 5,
};

static int
read_available_controllers (const char *path, libcrun_error_t *err)
{
  cleanup_close int fd;
  char *saveptr = NULL;
  const char *token;
  char *controllers;
  int available = 0;
  char buf[256];
  ssize_t ret;

  xasprintf (&controllers, "%s/cgroup.controllers", path);

  fd = TEMP_FAILURE_RETRY (open (controllers, O_RDONLY | O_CLOEXEC));
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "error opening file `%s`", path);

  ret = TEMP_FAILURE_RETRY (read (fd, buf, sizeof (buf) - 1));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error reading from file `%s`", path);
  buf[ret] = '\0';

  for (token = strtok_r (buf, " \n", &saveptr); token; token = strtok_r (NULL, " \n", &saveptr))
    {
      if (strcmp (token, "memory") == 0)
        available |= CGROUP_MEMORY;
      else if (strcmp (token, "cpu") == 0)
        available |= CGROUP_CPU;
      else if (strcmp (token, "cpuset") == 0)
        available |= CGROUP_CPUSET;
      else if (strcmp (token, "hugetlb") == 0)
        available |= CGROUP_HUGETLB;
      else if (strcmp (token, "pids") == 0)
        available |= CGROUP_PIDS;
      else if (strcmp (token, "io") == 0)
        available |= CGROUP_IO;
    }
  return available;
}

static int
write_controller_file (const char *path, int controllers_to_enable, libcrun_error_t *err)
{
  cleanup_free char *subtree_control = NULL;
  cleanup_free char *controllers = NULL;
  size_t controllers_len = 0;
  int ret;

  controllers_len = xasprintf (
      &controllers, "%s %s %s %s %s %s", (controllers_to_enable & CGROUP_CPU) ? "+cpu" : "",
      (controllers_to_enable & CGROUP_IO) ? "+io" : "", (controllers_to_enable & CGROUP_MEMORY) ? "+memory" : "",
      (controllers_to_enable & CGROUP_PIDS) ? "+pids" : "", (controllers_to_enable & CGROUP_CPUSET) ? "+cpuset" : "",
      (controllers_to_enable & CGROUP_HUGETLB) ? "+hugetlb" : "");

  xasprintf (&subtree_control, "%s/cgroup.subtree_control", path);
  ret = write_file (subtree_control, controllers, controllers_len, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_free char *controllers_copy = xmalloc (controllers_len + 1);
      int attempts_left;
      char *saveptr = NULL;
      const char *token;
      int e;

      e = crun_error_get_errno (err);
      if (e != EPERM && e != EACCES && e != EBUSY && e != ENOENT)
        return ret;

      /* ENOENT can mean both that the file doesn't exist or the controller is not present.  */
      if (e == ENOENT)
        {
          libcrun_error_t tmp_err = NULL;
          int exists;

          exists = crun_path_exists (subtree_control, &tmp_err);
          if (UNLIKELY (exists < 0))
            {
              crun_error_release (&tmp_err);
              return ret;
            }
          /* If the file doesn't exist, then return the original ENOENT.  */
          if (exists == 0)
            return ret;
        }

      crun_error_release (err);

      /* It seems the kernel can return EBUSY when a process was moved to a sub-cgroup
         and the controllers are enabled in its parent cgroup.  Retry a few times when
         it happens.  */
      for (attempts_left = 1000; attempts_left >= 0; attempts_left--)
        {
          int controllers_written;
          bool repeat = false;

          memcpy (controllers_copy, controllers, controllers_len);
          controllers_copy[controllers_len] = '\0';
          controllers_written = 0;

          /* Fallback to write each one individually.  */
          for (token = strtok_r (controllers_copy, " ", &saveptr); token; token = strtok_r (NULL, " ", &saveptr))
            {
              ret = write_file (subtree_control, token, strlen (token), err);
              if (ret < 0)
                {
                  if (crun_error_get_errno (err) == EBUSY)
                    repeat = true;
                  crun_error_release (err);

                  continue;
                }

              controllers_written++;
            }

          if (! repeat)
            break;

          /* If there was any controller written, just try once more without any delay.  */
          if (controllers_written > 0 && attempts_left > 2)
            {
              attempts_left = 1;
              continue;
            }

          if (attempts_left > 0)
            {
              struct timespec delay = {
                .tv_sec = 0,
                .tv_nsec = 1000000,
              };
              nanosleep (&delay, NULL);
            }
        }

      /* Refresh what controllers are available.  */
      return read_available_controllers (path, err);
    }

  /* All controllers were enabled successfully.  */
  return controllers_to_enable;
}

int
enable_controllers (const char *path, libcrun_error_t *err)
{
  cleanup_free char *tmp_path = NULL;
  char *it;
  int ret, controllers_to_enable;

  xasprintf (&tmp_path, "%s/", path);

  ret = read_available_controllers (CGROUP_ROOT, err);
  if (UNLIKELY (ret < 0))
    return ret;

  controllers_to_enable = ret;

  /* Enable all possible controllers in the root cgroup.  */
  ret = write_controller_file (CGROUP_ROOT, controllers_to_enable, err);
  if (UNLIKELY (ret < 0))
    {
      /* Enabling +cpu when there are realtime processes fail with EINVAL.  */
      if ((controllers_to_enable & CGROUP_CPU) && (crun_error_get_errno (err) == EINVAL))
        {
          crun_error_release (err);
          controllers_to_enable &= ~CGROUP_CPU;
          ret = write_controller_file (CGROUP_ROOT, controllers_to_enable, err);
        }
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (it = strchr (tmp_path + 1, '/'); it;)
    {
      cleanup_free char *cgroup_path = NULL;
      char *next_slash = strchr (it + 1, '/');

      *it = '\0';

      ret = append_paths (&cgroup_path, err, CGROUP_ROOT, tmp_path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = mkdir (cgroup_path, 0755);
      if (UNLIKELY (ret < 0 && errno != EEXIST))
        return crun_make_error (err, errno, "create `%s`", cgroup_path);

      if (next_slash)
        {
          ret = write_controller_file (cgroup_path, controllers_to_enable, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      *it = '/';
      it = next_slash;
    }
  return 0;
}

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

static int
enter_cgroup (int cgroup_mode, pid_t pid, pid_t init_pid, const char *path,
              bool create_if_missing, libcrun_error_t *err)
{
  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    return enter_cgroup_v2 (pid, init_pid, path, create_if_missing, err);

  return enter_cgroup_v1 (pid, path, create_if_missing, err);
}

int
libcrun_move_process_to_cgroup (pid_t pid, pid_t init_pid, char *path, libcrun_error_t *err)
{
  int cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (path == NULL || *path == '\0')
    return 0;

  return enter_cgroup (cgroup_mode, pid, init_pid, path, false, err);
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

static int
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

static int
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

static int
libcrun_cgroup_pause_unpause_with_mode (const char *cgroup_path, int cgroup_mode, const bool pause,
                                        libcrun_error_t *err)
{
  cleanup_free char *path = NULL;
  const char *state = "";
  int ret;

  if (cgroup_path == NULL || cgroup_path[0] == '\0')
    return crun_make_error (err, 0, "cannot %s the container without a cgroup", pause ? "pause" : "resume");

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      state = pause ? "1" : "0";
      ret = append_paths (&path, err, CGROUP_ROOT, cgroup_path, "cgroup.freeze", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      state = pause ? "FROZEN" : "THAWED";
      ret = append_paths (&path, err, CGROUP_ROOT "/freezer", cgroup_path, "freezer.state", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = write_file (path, state, strlen (state), err);
  if (ret >= 0)
    return 0;
  return ret;
}

static int
libcrun_cgroup_pause_unpause_path (const char *cgroup_path, const bool pause, libcrun_error_t *err)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  return libcrun_cgroup_pause_unpause_with_mode (cgroup_path, cgroup_mode, pause, err);
}

int
libcrun_cgroup_pause_unpause (struct libcrun_cgroup_status *status, const bool pause, libcrun_error_t *err)
{
  return libcrun_cgroup_pause_unpause_path (status->path, pause, err);
}

int
cgroup_killall_path (const char *path, int signal, libcrun_error_t *err)
{
  int ret;
  size_t i;
  cleanup_free pid_t *pids = NULL;

  if (path == NULL || *path == '\0')
    return 0;

  /* If the signal is SIGKILL, try to kill each process using the `cgroup.kill` file.  */
  if (signal == SIGKILL)
    {
      cleanup_free char *kill_file = NULL;

      ret = append_paths (&kill_file, err, CGROUP_ROOT, path, "cgroup.kill", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_file_with_flags (kill_file, 0, "1", 1, err);
      if (ret >= 0)
        return 0;

      crun_error_release (err);
    }

  ret = libcrun_cgroup_pause_unpause_path (path, true, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  ret = libcrun_cgroup_read_pids_from_path (path, true, &pids, err);
  if (UNLIKELY (ret < 0))
    {
      if (crun_error_get_errno (err) != ENOENT)
        return ret;

      /* If the file doesn't exist then the container was already killed.  */
      crun_error_release (err);
    }

  for (i = 0; pids && pids[i]; i++)
    {
      ret = kill (pids[i], signal);
      if (UNLIKELY (ret < 0 && errno != ESRCH))
        return crun_make_error (err, errno, "kill process %d", pids[i]);
    }

  ret = libcrun_cgroup_pause_unpause_path (path, false, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  return 0;
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
  int ret;

  switch (cgroup_status->manager)
    {
    case CGROUP_MANAGER_DISABLED:
      ret = libcrun_destroy_cgroup_disabled (cgroup_status, err);
      break;

    case CGROUP_MANAGER_SYSTEMD:
      ret = libcrun_destroy_cgroup_systemd (cgroup_status, err);
      break;

    case CGROUP_MANAGER_CGROUPFS:
      ret = libcrun_destroy_cgroup_cgroupfs (cgroup_status, err);
      break;

    default:
      return crun_make_error (err, EINVAL, "unknown cgroup manager specified %d", cgroup_status->manager);
    }

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

  switch (manager)
    {
    case CGROUP_MANAGER_DISABLED:
      ret = libcrun_cgroup_enter_disabled (args, status, err);
      break;

    case CGROUP_MANAGER_SYSTEMD:
      ret = libcrun_cgroup_enter_systemd (args, status, err);
      break;

    case CGROUP_MANAGER_CGROUPFS:
      ret = libcrun_cgroup_enter_cgroupfs (args, status, err);
      break;

    default:
      return crun_make_error (err, EINVAL, "unknown cgroup manager specified %d", manager);
    }

  if (LIKELY (ret >= 0))
    {
      bool need_chown = root_uid != (uid_t) -1 || root_gid != (gid_t) -1;
      if (status->path && cgroup_mode == CGROUP_MODE_UNIFIED && need_chown)
        {
          ret = chown_cgroups (status->path, root_uid, root_gid, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (args->resources && status->path)
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
