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

struct symlink_s
{
  const char *name;
  const char *target;
};

static struct symlink_s cgroup_symlinks[] = { { "cpu", "cpu,cpuacct" },
                                              { "cpuacct", "cpu,cpuacct" },
                                              { "net_cls", "net_cls,net_prio" },
                                              { "net_prio", "net_cls,net_prio" },
                                              { NULL, NULL } };

#ifndef CGROUP2_SUPER_MAGIC
#  define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef TMPFS_MAGIC
#  define TMPFS_MAGIC 0x01021994
#endif

static int
detect_cgroup_mode (libcrun_error_t *err)
{
  struct statfs stat;
  int ret;

  ret = statfs (CGROUP_ROOT, &stat);
  if (ret < 0)
    return crun_make_error (err, errno, "statfs '" CGROUP_ROOT "'");
  if (stat.f_type == CGROUP2_SUPER_MAGIC)
    return CGROUP_MODE_UNIFIED;
  if (stat.f_type != TMPFS_MAGIC)
    return crun_make_error (err, 0, "invalid file system type on '" CGROUP_ROOT "'");
  ret = statfs (CGROUP_ROOT "/unified", &stat);
  if (ret < 0 && errno != ENOENT)
    return crun_make_error (err, errno, "statfs '" CGROUP_ROOT "/unified'");
  if (ret < 0)
    return CGROUP_MODE_LEGACY;
  return stat.f_type == CGROUP2_SUPER_MAGIC ? CGROUP_MODE_HYBRID : CGROUP_MODE_LEGACY;
}

int
libcrun_get_cgroup_mode (libcrun_error_t *err)
{
  int tmp;
  static int cgroup_mode = 0;

  if (cgroup_mode)
    return cgroup_mode;

  tmp = detect_cgroup_mode (err);
  if (UNLIKELY (tmp < 0))
    return tmp;

  cgroup_mode = tmp;

  return cgroup_mode;
}

static int
is_rwm (const char *str, libcrun_error_t *err)
{
  const char *it;
  bool r = false;
  bool w = false;
  bool m = false;

  for (it = str; *it; it++)
    switch (*it)
      {
      case 'r':
        r = true;
        break;

      case 'w':
        w = true;
        break;

      case 'm':
        m = true;
        break;

      default:
        return crun_make_error (err, 0, "invalid mode specified `%s`", str);
      }

  return r && w && m ? 1 : 0;
}

enum
{
  CGROUP_MEMORY = 1 << 0,
  CGROUP_CPU = 1 << 1,
  CGROUP_HUGETLB = 1 << 2,
  CGROUP_CPUSET = 1 << 3,
  CGROUP_PIDS = 1 << 4,
  CGROUP_IO = 1 << 5,
};

int
libcrun_get_current_unified_cgroup (char **path, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  size_t content_size;
  char *from, *to;
  int ret;

  ret = read_all_file ("/proc/self/cgroup", &content, &content_size, err);
  if (UNLIKELY (ret < 0))
    return ret;

  from = strstr (content, "0::");
  if (UNLIKELY (from == NULL))
    return crun_make_error (err, 0, "cannot find cgroup2 for the current process");

  from += 3;
  to = strchr (from, '\n');
  if (UNLIKELY (to == NULL))
    return crun_make_error (err, 0, "cannot parse /proc/self/cgroup");
  *to = '\0';

  return append_paths (path, err, CGROUP_ROOT, from, NULL);
}

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
check_cgroup_v2_controller_available_wrapper (int ret, int cgroup_dirfd, const char *name, libcrun_error_t *err)
{
  if (ret == 0 || err == NULL)
    return 0;

  errno = crun_error_get_errno (err);

  /* If the file is not found, try to give a more meaningful error message.  */
  if (errno == ENOENT || errno == EPERM || errno == EACCES)
    {
      cleanup_free char *controllers = NULL;
      libcrun_error_t tmp_err = NULL;
      cleanup_free char *key = NULL;
      char *saveptr = NULL;
      bool found = false;
      const char *token;
      char *it;

      /* Check if the specified controller is enabled.  */
      key = xstrdup (name);

      it = strchr (key, '.');
      if (it == NULL)
        {
          crun_error_release (err);
          return crun_make_error (err, 0, "the specified key has not the form CONTROLLER.VALUE `%s`", name);
        }
      *it = '\0';

      /* cgroup. files are not part of a controller.  Return the original error.  */
      if (strcmp (key, "cgroup") == 0)
        return ret;

      /* If the cgroup.controllers file cannot be read, return the original error.  */
      if (read_all_file_at (cgroup_dirfd, "cgroup.controllers", &controllers, NULL, &tmp_err) < 0)
        {
          crun_error_release (&tmp_err);
          return ret;
        }
      for (token = strtok_r (controllers, " \n", &saveptr); token; token = strtok_r (NULL, " \n", &saveptr))
        {
          if (strcmp (token, key) == 0)
            {
              found = true;
              break;
            }
        }
      if (! found)
        {
          crun_error_release (err);
          return crun_make_error (err, 0, "the requested cgroup controller `%s` is not available", key);
        }
    }
  return ret;
}

static int
write_file_and_check_controllers_at (bool cgroup2, int dirfd, const char *name, const void *data, size_t len,
                                     libcrun_error_t *err)
{
  int ret;

  ret = write_file_at (dirfd, name, data, len, err);
  if (cgroup2)
    return check_cgroup_v2_controller_available_wrapper (ret, dirfd, name, err);
  return ret;
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
move_process_to_cgroup (pid_t pid, const char *subsystem, const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path_procs = NULL;
  char pid_str[16];
  int ret;

  ret = append_paths (&cgroup_path_procs, err, CGROUP_ROOT, subsystem ? subsystem : "", path ? path : "",
                      "cgroup.procs", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  sprintf (pid_str, "%d", pid);

  return write_file (cgroup_path_procs, pid_str, strlen (pid_str), err);
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
is_rootless (libcrun_error_t *err)
{
  if (geteuid ())
    return 1;

  return check_running_in_user_namespace (err);
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

int
chown_cgroups (const char *path, uid_t uid, gid_t gid, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_free char *delegate = NULL;
  cleanup_close int dfd = -1;
  size_t delegate_size;
  char *saveptr = NULL;
  char *name;
  int ret;

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  dfd = open (cgroup_path, O_PATH);

  ret = read_all_file ("/sys/kernel/cgroup/delegate", &delegate, &delegate_size, err);
  if (UNLIKELY (ret < 0))
    {
      if (crun_error_get_errno (err) == ENOENT)
        {
          crun_error_release (err);
          return 0;
        }
      return ret;
    }

  ret = fchownat (dfd, "", uid, gid, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot chown `%s`", cgroup_path);

  for (name = strtok_r (delegate, "\n", &saveptr); name; name = strtok_r (NULL, "\n", &saveptr))
    {
      ret = fchownat (dfd, name, uid, gid, AT_SYMLINK_NOFOLLOW);
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOENT)
            continue;

          return crun_make_error (err, errno, "cannot chown `%s/%s`", cgroup_path, name);
        }
    }

  return 0;
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

/* same semantic as strtok_r.  */
static bool
read_proc_cgroup (char *content, char **saveptr, char **id, char **controller_list, char **path)
{
  char *it;

  it = strtok_r (content, "\n", saveptr);
  if (it == NULL)
    return false;

  if (id)
    *id = it;

  it = strchr (it, ':');
  if (it == NULL)
    return false;
  *it++ = '\0';

  if (controller_list)
    *controller_list = it;

  it = strchr (it, ':');
  if (it == NULL)
    return false;
  *it++ = '\0';

  if (path)
    *path = it;

  return true;
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
enter_cgroup (int cgroup_mode, pid_t pid, pid_t init_pid, const char *path, bool create_if_missing,
              libcrun_error_t *err)
{
  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    return enter_cgroup_v2 (pid, init_pid, path, create_if_missing, err);

  return enter_cgroup_v1 (pid, path, create_if_missing, err);
}

int
libcrun_cgroups_create_symlinks (int dirfd, libcrun_error_t *err)
{
  int i;

  for (i = 0; cgroup_symlinks[i].name; i++)
    {
      int ret;

      ret = symlinkat (cgroup_symlinks[i].target, dirfd, cgroup_symlinks[i].name);
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOENT || errno == EEXIST)
            continue;
          return crun_make_error (err, errno, "symlinkat %s", cgroup_symlinks[i].name);
        }
    }
  return 0;
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

static int
libcrun_cgroup_enter_disabled (struct libcrun_cgroup_args *args arg_unused, struct libcrun_cgroup_status *out, libcrun_error_t *err arg_unused)
{
  out->path = NULL;
  return 0;
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
read_pids_cgroup (int dfd, bool recurse, pid_t **pids, size_t *n_pids, size_t *allocated, libcrun_error_t *err)
{
  __attribute__ ((unused)) cleanup_close int clean_dfd = dfd;
  cleanup_close int tasksfd = -1;
  cleanup_free char *buffer = NULL;
  char *saveptr = NULL;
  size_t n_new_pids;
  size_t len;
  char *it;
  int ret;

  tasksfd = openat (dfd, "cgroup.procs", O_RDONLY | O_CLOEXEC);
  if (tasksfd < 0)
    return crun_make_error (err, errno, "open cgroup.procs");

  ret = read_all_fd (tasksfd, "cgroup.procs", &buffer, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (len == 0)
    return 0;

  for (n_new_pids = 0, it = buffer; it; it = strchr (it + 1, '\n'))
    n_new_pids++;

  if (*allocated < *n_pids + n_new_pids + 1)
    {
      *allocated = *n_pids + n_new_pids + 1;
      *pids = xrealloc (*pids, sizeof (pid_t) * *allocated);
    }

  for (it = strtok_r (buffer, "\n", &saveptr); it; it = strtok_r (NULL, "\n", &saveptr))
    {
      pid_t pid = strtoul (it, NULL, 10);

      if (pid > 0)
        (*pids)[(*n_pids)++] = pid;
    }
  (*pids)[*n_pids] = 0;

  if (recurse)
    {
      cleanup_dir DIR *dir = NULL;
      struct dirent *de;

      dir = fdopendir (dfd);
      if (UNLIKELY (dir == NULL))
        return crun_make_error (err, errno, "open cgroup sub-directory");
      /* Now dir owns the dfd descriptor.  */
      clean_dfd = -1;

      for (de = readdir (dir); de; de = readdir (dir))
        {
          int nfd;

          if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
            continue;

          if (de->d_type != DT_DIR)
            continue;

          nfd = openat (dirfd (dir), de->d_name, O_DIRECTORY | O_CLOEXEC);
          if (UNLIKELY (nfd < 0))
            return crun_make_error (err, errno, "open cgroup directory `%s`", de->d_name);
          ret = read_pids_cgroup (nfd, recurse, pids, n_pids, allocated, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  return 0;
}

int
libcrun_cgroup_read_pids_from_path (const char *path, bool recurse, pid_t **pids, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  size_t n_pids, allocated;
  int dirfd;
  int mode;
  int ret;

  if (path == NULL || *path == '\0')
    return 0;

  mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (mode < 0))
    return mode;

  switch (mode)
    {
    case CGROUP_MODE_UNIFIED:
      ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      break;

    case CGROUP_MODE_HYBRID:
    case CGROUP_MODE_LEGACY:
      ret = append_paths (&cgroup_path, err, CGROUP_ROOT "/memory", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      break;

    default:
      return crun_make_error (err, 0, "invalid cgroup mode %d", mode);
    }

  dirfd = open (cgroup_path, O_DIRECTORY | O_CLOEXEC);
  if (dirfd < 0)
    return crun_make_error (err, errno, "open `%s`", cgroup_path);

  n_pids = 0;
  allocated = 0;

  return read_pids_cgroup (dirfd, recurse, pids, &n_pids, &allocated, err);
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

static int
rmdir_all_fd (int dfd)
{
  cleanup_dir DIR *dir = NULL;
  struct dirent *next;

  dir = fdopendir (dfd);
  if (dir == NULL)
    return -1;

  dfd = dirfd (dir);

  for (next = readdir (dir); next; next = readdir (dir))
    {
      const char *name = next->d_name;
      int ret;

      if (name[0] == '.' && name[1] == '\0')
        continue;
      if (name[0] == '.' && name[1] == '.' && name[2] == '\0')
        continue;

      if (next->d_type != DT_DIR)
        continue;

      ret = unlinkat (dfd, name, AT_REMOVEDIR);
      if (ret < 0 && errno == EBUSY)
        {
          cleanup_free pid_t *pids = NULL;
          libcrun_error_t tmp_err = NULL;
          size_t i, n_pids = 0, allocated = 0;
          cleanup_close int child_dfd = -1;
          int child_dfd_clone;

          child_dfd = openat (dfd, name, O_DIRECTORY | O_CLOEXEC);
          if (child_dfd < 0)
            return child_dfd;

          /* read_pids_cgroup takes ownership for the fd, so dup it.  */
          child_dfd_clone = dup (child_dfd);
          if (LIKELY (child_dfd_clone >= 0))
            {
              ret = read_pids_cgroup (child_dfd_clone, true, &pids, &n_pids, &allocated, &tmp_err);
              if (UNLIKELY (ret < 0))
                {
                  crun_error_release (&tmp_err);
                  continue;
                }
            }

          for (i = 0; i < n_pids; i++)
            kill (pids[i], SIGKILL);

          return rmdir_all_fd (child_dfd);
        }
    }
  return 0;
}

static int
rmdir_all (const char *path)
{
  int ret;
  cleanup_close int dfd = open (path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (dfd < 0))
    return dfd;

  ret = rmdir_all_fd (dfd);
  if (UNLIKELY (ret < 0))
    return ret;

  return rmdir (path);
}

int
destroy_cgroup_path (const char *path, int mode, libcrun_error_t *err)
{
  bool repeat = true;
  int ret;

  do
    {
      repeat = false;

      if (mode == CGROUP_MODE_UNIFIED)
        {
          cleanup_free char *cgroup_path = NULL;

          ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
          if (UNLIKELY (ret < 0))
            return ret;
          ret = rmdir (cgroup_path);
          if (ret < 0 && errno == EBUSY)
            {
              ret = rmdir_all (cgroup_path);
              if (ret < 0)
                repeat = true;
            }
        }
      else
        {
          cleanup_free char *content = NULL;
          size_t content_size;
          char *controller;
          char *saveptr;
          bool has_data;

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
              cleanup_free char *cgroup_path = NULL;
              char *subsystem;
              if (has_prefix (controller, "name="))
                controller += 5;

              subsystem = controller[0] == '\0' ? "unified" : controller;
              if (mode == CGROUP_MODE_LEGACY && strcmp (subsystem, "unified") == 0)
                continue;

              ret = append_paths (&cgroup_path, err, CGROUP_ROOT, subsystem, path, NULL);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = rmdir (cgroup_path);
              if (ret < 0 && errno == EBUSY)
                {
                  ret = rmdir_all (cgroup_path);
                  if (ret < 0)
                    repeat = true;
                }
            }
        }

      if (repeat)
        {
          struct timespec req = {
            .tv_sec = 0,
            .tv_nsec = 100000,
          };

          nanosleep (&req, NULL);

          ret = cgroup_killall_path (path, SIGKILL, err);
          if (UNLIKELY (ret < 0))
            crun_error_release (err);
        }
  } while (repeat);

  return 0;
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

static int
libcrun_destroy_cgroup_disabled (struct libcrun_cgroup_status *cgroup_status arg_unused,
                                 libcrun_error_t *err arg_unused)
{
  return 0;
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

/* The parser generates different structs but they are really all the same.  */
typedef runtime_spec_schema_defs_linux_block_io_device_throttle throttling_s;

static int
write_blkio_v1_resources_throttling (int dirfd, const char *name, throttling_s **throttling, size_t throttling_len,
                                     libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  cleanup_close int fd = -1;

  if (throttling == NULL)
    return 0;

  fd = openat (dirfd, name, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open `%s`", name);

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu64 "\n", throttling[i]->major, throttling[i]->minor,
                     throttling[i]->rate);

      ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write `%s`", name);
    }
  return 0;
}

static int
write_blkio_v2_resources_throttling (int fd, const char *name, throttling_s **throttling, size_t throttling_len,
                                     libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;

  if (throttling == NULL)
    return 0;

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %s=%" PRIu64 "\n", throttling[i]->major, throttling[i]->minor,
                     name, throttling[i]->rate);

      ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write `%s`", name);
    }
  return 0;
}

static int
write_blkio_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_block_io *blkio,
                       libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;

  if (blkio->weight)
    {
      uint32_t val = blkio->weight;

      len = sprintf (fmt_buf, "%" PRIu32, val);
      ret = write_file_at (dirfd, cgroup2 ? "io.bfq.weight" : "blkio.weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->leaf_weight)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set leaf_weight with cgroupv2");
      len = sprintf (fmt_buf, "%d", blkio->leaf_weight);
      ret = write_file_at (dirfd, "blkio.leaf_weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->weight_device_len)
    {
      if (cgroup2)
        {
          cleanup_close int wfd = -1;
          size_t i;

          wfd = openat (dirfd, "io.bfq.weight", O_WRONLY);
          if (UNLIKELY (wfd < 0))
            return crun_make_error (err, errno, "open io.weight");
          for (i = 0; i < blkio->weight_device_len; i++)
            {
              uint32_t w = blkio->weight_device[i]->weight;

              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %i\n", blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor, w);
              ret = TEMP_FAILURE_RETRY (write (wfd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write io.weight");

              /* Ignore blkio->weight_device[i]->leaf_weight.  */
            }
        }
      else
        {
          cleanup_close int w_device_fd = -1;
          cleanup_close int w_leafdevice_fd = -1;
          size_t i;

          w_device_fd = openat (dirfd, "blkio.weight_device", O_WRONLY);
          if (UNLIKELY (w_device_fd < 0))
            return crun_make_error (err, errno, "open blkio.weight_device");

          w_leafdevice_fd = openat (dirfd, "blkio.leaf_weight_device", O_WRONLY);
          if (UNLIKELY (w_leafdevice_fd < 0))
            return crun_make_error (err, errno, "open blkio.leaf_weight_device");

          for (i = 0; i < blkio->weight_device_len; i++)
            {
              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu16 "\n", blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor, blkio->weight_device[i]->weight);
              ret = TEMP_FAILURE_RETRY (write (w_device_fd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.weight_device");

              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu16 "\n", blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor, blkio->weight_device[i]->leaf_weight);
              ret = TEMP_FAILURE_RETRY (write (w_leafdevice_fd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.leaf_weight_device");
            }
        }
    }
  if (cgroup2)
    {
      cleanup_close int wfd = -1;
      const char *name = "io.max";

      wfd = openat (dirfd, name, O_WRONLY);
      if (UNLIKELY (wfd < 0))
        {
          ret = crun_make_error (err, errno, "open `%s`", name);
          return check_cgroup_v2_controller_available_wrapper (ret, dirfd, name, err);
        }

      ret = write_blkio_v2_resources_throttling (wfd, "rbps", (throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wbps", (throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "riops", (throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wiops", (throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_bps_device",
                                                 (throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_bps_device",
                                                 (throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_iops_device",
                                                 (throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_iops_device",
                                                 (throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_network_resources (int dirfd_netclass, int dirfd_netprio, runtime_spec_schema_config_linux_resources_network *net,
                         libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
  if (net->class_id)
    {
      len = sprintf (fmt_buf, "%d", net->class_id);
      ret = write_file_at (dirfd_netclass, "net_cls.classid", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (net->priorities_len)
    {
      size_t i;
      cleanup_close int fd = -1;
      fd = openat (dirfd_netprio, "net_prio.ifpriomap", O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open `net_prio.ifpriomap`");

      for (i = 0; i < net->priorities_len; i++)
        {
          len = sprintf (fmt_buf, "%s %d\n", net->priorities[i]->name, net->priorities[i]->priority);
          ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write net_prio.ifpriomap");
        }
    }

  return 0;
}

static int
write_hugetlb_resources (int dirfd, bool cgroup2,
                         runtime_spec_schema_config_linux_resources_hugepage_limits_element **htlb, size_t htlb_len,
                         libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  for (i = 0; i < htlb_len; i++)
    {
      cleanup_free char *filename = NULL;
      const char *suffix;
      size_t len;
      int ret;

      suffix = cgroup2 ? "max" : "limit_in_bytes";

      xasprintf (&filename, "hugetlb.%s.%s", htlb[i]->page_size, suffix);

      len = sprintf (fmt_buf, "%" PRIu64, htlb[i]->limit);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, filename, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_devices_resources_v1 (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                            libcrun_error_t *err)
{
  size_t i, len;
  int ret;
  char *default_devices[] = {
    "c *:* m",
    "b *:* m",
    "c 1:3 rwm",
    "c 1:8 rwm",
    "c 1:7 rwm",
    "c 5:0 rwm",
    "c 1:5 rwm",
    "c 1:9 rwm",
    "c 5:1 rwm",
    "c 136:* rwm",
    "c 5:2 rwm",
    "c 10:200 rwm",
    NULL
  };

  for (i = 0; i < devs_len; i++)
    {
      /* It is plenty of room for "TYPE MAJOR:MINOR ACCESS", where type is one char, and ACCESS is at most 3.   */
#define FMT_BUF_LEN 64
      char fmt_buf[FMT_BUF_LEN];
      const char *file = devs[i]->allow ? "devices.allow" : "devices.deny";

      if (devs[i]->type == NULL || devs[i]->type[0] == 'a')
        {
          strcpy (fmt_buf, "a");
          len = 1;
        }
      else
        {
          char fmt_buf_major[16];
          char fmt_buf_minor[16];

#define FMT_DEV(x, b)               \
  do                                \
    {                               \
      if (x##_present)              \
        sprintf (b, "%" PRIi64, x); \
      else                          \
        strcpy (b, "*");            \
  } while (0)

          FMT_DEV (devs[i]->major, fmt_buf_major);
          FMT_DEV (devs[i]->minor, fmt_buf_minor);

          len = snprintf (fmt_buf, FMT_BUF_LEN - 1, "%s %s:%s %s", devs[i]->type, fmt_buf_major, fmt_buf_minor,
                          devs[i]->access);
          /* Make sure it is still a NUL terminated string.  */
          fmt_buf[len] = '\0';
        }
      ret = write_file_at (dirfd, file, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (i = 0; default_devices[i]; i++)
    {
      ret = write_file_at (dirfd, "devices.allow", default_devices[i], strlen (default_devices[i]), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_devices_resources_v2_internal (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                                     libcrun_error_t *err)
{
  int i, ret;
  cleanup_free struct bpf_program *program = NULL;
  struct default_dev_s
  {
    char type;
    int major;
    int minor;
    const char *access;
  };
  struct default_dev_s default_devices[] = {
    { 'c', -1, -1, "m" },
    { 'b', -1, -1, "m" },
    { 'c', 1, 3, "rwm" },
    { 'c', 1, 8, "rwm" },
    { 'c', 1, 7, "rwm" },
    { 'c', 5, 0, "rwm" },
    { 'c', 1, 5, "rwm" },
    { 'c', 1, 9, "rwm" },
    { 'c', 5, 1, "rwm" },
    { 'c', 136, -1, "rwm" },
    { 'c', 5, 2, "rwm" },
    { 'c', 10, 200, "rwm" },
  };

  program = bpf_program_new (2048);

  program = bpf_program_init_dev (program, err);
  if (UNLIKELY (program == NULL))
    return -1;

  for (i = (sizeof (default_devices) / sizeof (default_devices[0])) - 1; i >= 0; i--)
    {
      program = bpf_program_append_dev (program, default_devices[i].access, default_devices[i].type,
                                        default_devices[i].major, default_devices[i].minor, true, err);
      if (UNLIKELY (program == NULL))
        return -1;
    }
  for (i = devs_len - 1; i >= 0; i--)
    {
      char type = 'a';
      int minor = -1, major = -1;
      if (devs[i]->type != NULL)
        type = devs[i]->type[0];

      if (devs[i]->major_present)
        major = devs[i]->major;
      if (devs[i]->minor_present)
        minor = devs[i]->minor;

      program = bpf_program_append_dev (program, devs[i]->access, type, major, minor, devs[i]->allow, err);
      if (UNLIKELY (program == NULL))
        return -1;
    }

  program = bpf_program_complete_dev (program, err);
  if (UNLIKELY (program == NULL))
    return -1;

  ret = libcrun_ebpf_load (program, dirfd, NULL, err);
  if (ret < 0)
    return ret;

  return 0;
}

static int
write_devices_resources_v2 (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                            libcrun_error_t *err)
{
  int ret;
  size_t i;
  bool can_skip = true;

  ret = write_devices_resources_v2_internal (dirfd, devs, devs_len, err);
  if (LIKELY (ret == 0))
    return 0;

  /* If writing the resources ebpf failed, check if it is fine to ignore the error.  */
  for (i = 0; i < devs_len; i++)
    {
      if (devs[i]->allow_present && ! devs[i]->allow)
        {
          can_skip = false;
          break;
        }
    }

  if (! can_skip)
    {
      libcrun_error_t tmp_err = NULL;
      int rootless;

      rootless = is_rootless (&tmp_err);
      if (UNLIKELY (rootless < 0))
        {
          crun_error_release (err);
          *err = tmp_err;
          return ret;
        }
      if (rootless)
        can_skip = true;
    }

  if (can_skip)
    {
      crun_error_release (err);
      ret = 0;
    }

  return ret;
}

static int
write_devices_resources (int dirfd, bool cgroup2, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                         libcrun_error_t *err)
{
  int ret;

  if (cgroup2)
    ret = write_devices_resources_v2 (dirfd, devs, devs_len, err);
  else
    ret = write_devices_resources_v1 (dirfd, devs, devs_len, err);
  if (UNLIKELY (ret < 0))
    {
      libcrun_error_t tmp_err = NULL;
      int rootless;

      rootless = is_rootless (&tmp_err);
      if (UNLIKELY (rootless < 0))
        {
          crun_error_release (&tmp_err);
          return ret;
        }

      if (rootless)
        {
          crun_error_release (err);
          ret = 0;
        }
    }
  return ret;
}

/* use for cgroupv2 files with .min, .max, .low, or .high suffix */
static int
cg_itoa (char *buf, int64_t value, bool cgroup2)
{
  if (! (cgroup2 && value == -1))
    return sprintf (buf, "%" PRIi64, value);

  memcpy (buf, "max", 4);
  return 3;
}

static int
write_memory (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory, libcrun_error_t *err)
{
  char limit_buf[32];
  size_t limit_buf_len;

  if (! memory->limit_present)
    return 0;

  limit_buf_len = cg_itoa (limit_buf, memory->limit, cgroup2);

  return write_file_at (dirfd, cgroup2 ? "memory.max" : "memory.limit_in_bytes", limit_buf, limit_buf_len, err);
}

static int
write_memory_swap (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory,
                   libcrun_error_t *err)
{
  int64_t swap;
  char swap_buf[32];
  size_t swap_buf_len;

  if (! memory->swap_present)
    return 0;

  swap = memory->swap;
  if (cgroup2 && memory->swap != -1)
    {
      if (! memory->limit_present)
        return crun_make_error (err, 0, "cannot set swap limit without the memory limit");
      if (memory->swap < memory->limit)
        return crun_make_error (err, 0, "cannot set memory+swap limit less than the memory limit");

      swap -= memory->limit;
    }

  swap_buf_len = cg_itoa (swap_buf, swap, cgroup2);

  return write_file_and_check_controllers_at (
      cgroup2, dirfd, cgroup2 ? "memory.swap.max" : "memory.memsw.limit_in_bytes", swap_buf, swap_buf_len, err);
}

static int
write_memory_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory,
                        libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[32];
  bool memory_limits_written = false;

  if (memory->limit_present)
    {
      ret = write_memory (dirfd, cgroup2, memory, err);
      if (ret >= 0)
        memory_limits_written = true;
      else
        {
          if (cgroup2 || crun_error_get_errno (err) != EINVAL)
            return ret;

          /*
            If we get an EINVAL error on cgroup v1 we reverse
            the order we write the memory limit and the swap.
            Attempt to write again the memory limit once the memory
            swap is written.
          */
          crun_error_release (err);
        }
    }

  ret = write_memory_swap (dirfd, cgroup2, memory, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (memory->limit_present && ! memory_limits_written)
    {
      ret = write_memory (dirfd, cgroup2, memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->kernel_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set kernel memory with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->kernel);
      ret = write_file_at (dirfd, "memory.kmem.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  // allows users set use_hierarchy as 0 when defined as false in spec.
  // if use_hierarchy is not defined in spec value defaults to 1 (True).
  // Note: users can only toggle use_hierarchy if the parent cgroup has use_hierarchy configured as 0.
  if (memory->use_hierarchy_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set useHierarchy memory with cgroupv2");

      ret = write_file_at (dirfd, "memory.use_hierarchy", (memory->use_hierarchy) ? "1" : "0", 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->reservation_present)
    {
      len = sprintf (fmt_buf, "%" PRIu64, memory->reservation);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, cgroup2 ? "memory.low" : "memory.soft_limit_in_bytes",
                                                 fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->disable_oom_killer)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot disable OOM killer with cgroupv2");

      ret = write_file_at (dirfd, "memory.oom_control", "1", 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->kernel_tcp_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set kernel TCP with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->kernel_tcp);
      ret = write_file_at (dirfd, "memory.kmem.tcp.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->swappiness_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set memory swappiness with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->swappiness);
      ret = write_file_at (dirfd, "memory.swappiness", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_pids_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_pids *pids,
                      libcrun_error_t *err)
{
  if (pids->limit)
    {
      char fmt_buf[32];
      size_t len;
      int ret;

      len = cg_itoa (fmt_buf, pids->limit, cgroup2);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, "pids.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_cpu_resources (int dirfd_cpu, bool cgroup2, runtime_spec_schema_config_linux_resources_cpu *cpu,
                     libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[64];
  int64_t period = -1;
  int64_t quota = -1;

  /* convert linearly from 2-262144 to 1-10000.  */
#define CONVERT_SHARES_TO_CGROUPS_V2(x) (1 + (((x) -2) * 9999) / 262142)

  if (cpu->shares)
    {
      uint32_t val = cpu->shares;

      if (cgroup2)
        val = CONVERT_SHARES_TO_CGROUPS_V2 (val);

      len = sprintf (fmt_buf, "%u", val);

      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpu, cgroup2 ? "cpu.weight" : "cpu.shares", fmt_buf,
                                                 len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->period)
    {
      if (cgroup2)
        period = cpu->period;
      else
        {
          len = sprintf (fmt_buf, "%" PRIu64, cpu->period);
          ret = write_file_at (dirfd_cpu, "cpu.cfs_period_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (cpu->quota)
    {
      if (cgroup2)
        quota = cpu->quota;
      else
        {
          len = sprintf (fmt_buf, "%" PRIu64, cpu->quota);
          ret = write_file_at (dirfd_cpu, "cpu.cfs_quota_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (cpu->realtime_period)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "realtime period not supported on cgroupv2");
      len = sprintf (fmt_buf, "%" PRIu64, cpu->realtime_period);
      ret = write_file_at (dirfd_cpu, "cpu.rt_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->realtime_runtime)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "realtime runtime not supported on cgroupv2");
      len = sprintf (fmt_buf, "%" PRIu64, cpu->realtime_runtime);
      ret = write_file_at (dirfd_cpu, "cpu.rt_runtime_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (cgroup2 && (quota > 0 || period > 0))
    {
      if (period < 0)
        period = 100000;
      if (quota < 0)
        len = sprintf (fmt_buf, "max %" PRIi64, period);
      else
        len = sprintf (fmt_buf, "%" PRIi64 " %" PRIi64, quota, period);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpu, "cpu.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_cpuset_resources (int dirfd_cpuset, int cgroup2, runtime_spec_schema_config_linux_resources_cpu *cpu,
                        libcrun_error_t *err)
{
  int ret;

  if (cpu->cpus)
    {
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpuset, "cpuset.cpus", cpu->cpus, strlen (cpu->cpus),
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->mems)
    {
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpuset, "cpuset.mems", cpu->mems, strlen (cpu->mems),
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
update_cgroup_v1_resources (runtime_spec_schema_config_linux_resources *resources, const char *path, libcrun_error_t *err)
{
  int ret;

  if (resources->block_io)
    {
      cleanup_free char *path_to_blkio = NULL;
      cleanup_close int dirfd_blkio = -1;
      runtime_spec_schema_config_linux_resources_block_io *blkio = resources->block_io;

      ret = append_paths (&path_to_blkio, err, CGROUP_ROOT "/blkio", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_blkio = open (path_to_blkio, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_blkio < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_blkio);

      ret = write_blkio_resources (dirfd_blkio, false, blkio, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->network)
    {
      cleanup_free char *path_to_netclass = NULL;
      cleanup_close int dirfd_netclass = -1;
      cleanup_free char *path_to_netprio = NULL;
      cleanup_close int dirfd_netprio = -1;
      runtime_spec_schema_config_linux_resources_network *network = resources->network;

      ret = append_paths (&path_to_netclass, err, CGROUP_ROOT "/net_cls", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&path_to_netprio, err, CGROUP_ROOT "/net_prio", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_netclass = open (path_to_netclass, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_netclass < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_netclass);

      dirfd_netprio = open (path_to_netprio, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_netprio < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_netprio);

      ret = write_network_resources (dirfd_netclass, dirfd_netprio, network, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->hugepage_limits_len)
    {
      cleanup_free char *path_to_htlb = NULL;
      cleanup_close int dirfd_htlb = -1;

      ret = append_paths (&path_to_htlb, err, CGROUP_ROOT "/hugetlb", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      dirfd_htlb = open (path_to_htlb, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_htlb < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_htlb);

      ret = write_hugetlb_resources (dirfd_htlb, false, resources->hugepage_limits, resources->hugepage_limits_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->devices_len)
    {
      cleanup_free char *path_to_devs = NULL;
      cleanup_close int dirfd_devs = -1;

      ret = append_paths (&path_to_devs, err, CGROUP_ROOT "/devices", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_devs = open (path_to_devs, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_devs < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_devs);

      ret = write_devices_resources (dirfd_devs, false, resources->devices, resources->devices_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      cleanup_free char *path_to_mem = NULL;
      cleanup_close int dirfd_mem = -1;

      ret = append_paths (&path_to_mem, err, CGROUP_ROOT "/memory", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_mem = open (path_to_mem, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_mem < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_mem);

      ret = write_memory_resources (dirfd_mem, false, resources->memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->pids)
    {
      cleanup_free char *path_to_pid = NULL;
      cleanup_close int dirfd_pid = -1;

      ret = append_paths (&path_to_pid, err, CGROUP_ROOT "/pids", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_pid = open (path_to_pid, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_pid < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_pid);

      ret = write_pids_resources (dirfd_pid, false, resources->pids, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->cpu)
    {
      cleanup_free char *path_to_cpu = NULL;
      cleanup_close int dirfd_cpu = -1;
      cleanup_free char *path_to_cpuset = NULL;
      cleanup_close int dirfd_cpuset = -1;

      ret = append_paths (&path_to_cpu, err, CGROUP_ROOT "/cpu", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_cpu = open (path_to_cpu, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpu < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_cpu);
      ret = write_cpu_resources (dirfd_cpu, false, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (resources->cpu->cpus == NULL && resources->cpu->mems == NULL)
        return 0;

      ret = append_paths (&path_to_cpuset, err, CGROUP_ROOT "/cpuset", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_cpuset = open (path_to_cpuset, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpuset < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_cpuset);

      ret = write_cpuset_resources (dirfd_cpuset, false, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->unified && resources->unified->len > 0)
    return crun_make_error (err, 0, "invalid configuration: cannot use unified on cgroup v1");

  return 0;
}

static int
write_unified_resources (int cgroup_dirfd, runtime_spec_schema_config_linux_resources *resources, libcrun_error_t *err)
{
  size_t i;
  int ret;

  for (i = 0; i < resources->unified->len; i++)
    {
      size_t len;

      if (strchr (resources->unified->keys[i], '/'))
        return crun_make_error (err, 0, "key `%s` must be a file name without any slash", resources->unified->keys[i]);

      len = strlen (resources->unified->values[i]);
      ret = write_file_and_check_controllers_at (true, cgroup_dirfd, resources->unified->keys[i],
                                                 resources->unified->values[i], len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
update_cgroup_v2_resources (runtime_spec_schema_config_linux_resources *resources, const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int cgroup_dirfd = -1;
  int ret;

  if (resources->network)
    return crun_make_error (err, 0, "network limits not supported on cgroupv2");

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  cgroup_dirfd = open (cgroup_path, O_DIRECTORY);
  if (UNLIKELY (cgroup_dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", cgroup_path);

  if (resources->devices_len)
    {
      ret = write_devices_resources (cgroup_dirfd, true, resources->devices, resources->devices_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      ret = write_memory_resources (cgroup_dirfd, true, resources->memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->pids)
    {
      ret = write_pids_resources (cgroup_dirfd, true, resources->pids, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->cpu)
    {
      ret = write_cpu_resources (cgroup_dirfd, true, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_cpuset_resources (cgroup_dirfd, true, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->block_io)
    {
      ret = write_blkio_resources (cgroup_dirfd, true, resources->block_io, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->hugepage_limits_len)
    {
      ret = write_hugetlb_resources (cgroup_dirfd, true, resources->hugepage_limits, resources->hugepage_limits_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Write unified resources if any.  They have higher precedence and override any previous setting.  */
  if (resources->unified)
    {
      ret = write_unified_resources (cgroup_dirfd, resources, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

int
update_cgroup_resources (const char *path,
                         runtime_spec_schema_config_linux_resources *resources,
                         libcrun_error_t *err)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (path == NULL)
    {
      size_t i;

      if (resources->block_io || resources->network || resources->hugepage_limits_len || resources->memory
          || resources->pids || resources->cpu)
        return crun_make_error (err, 0, "cannot set limits without cgroups");

      for (i = 0; i < resources->devices_len; i++)
        {
          int rwm;

          rwm = is_rwm (resources->devices[i]->access, err);
          if (UNLIKELY (rwm < 0))
            return rwm;

          if (rwm == 0)
            return crun_make_error (err, 0, "cannot set limits without cgroups");
        }

      return 0;
    }
  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      return update_cgroup_v2_resources (resources, path, err);

    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      return update_cgroup_v1_resources (resources, path, err);

    default:
      return crun_make_error (err, 0, "invalid cgroup mode %d", cgroup_mode);
    }
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
