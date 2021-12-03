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
#include "cgroup-setup.h"
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

/* same semantic as strtok_r.  */
bool
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

int
libcrun_cgroup_pause_unpause_path (const char *cgroup_path, const bool pause, libcrun_error_t *err)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  return libcrun_cgroup_pause_unpause_with_mode (cgroup_path, cgroup_mode, pause, err);
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
