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

#define _GNU_SOURCE

#include <config.h>
#include "cgroup.h"
#include "ebpf.h"
#include "utils.h"
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/vfs.h>
#include <inttypes.h>

#ifdef HAVE_SYSTEMD
# include <systemd/sd-bus.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>

static const cgroups_subsystem_t cgroups_subsystems[] = { "cpuset", "cpu", "devices", "pids", "memory",
                                                          "net_cls,net_prio", "freezer", "blkio",
                                                          "hugetlb", "cpu,cpuacct", "perf_event",
                                                          "unified", NULL};

const cgroups_subsystem_t *
libcrun_get_cgroups_subsystems (libcrun_error_t *err)
{
  return cgroups_subsystems;
}

struct symlink_s
{
  const char *name;
  const char *target;
};

static struct symlink_s cgroup_symlinks[] = {
  { "cpu", "cpu,cpuacct" },
  { "cpuacct", "cpu,cpuacct" },
  { "net_cls", "net_cls,net_prio" },
  { "net_prio", "net_cls,net_prio" },
  { NULL, NULL }
};

#ifndef CGROUP2_SUPER_MAGIC
# define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef TMPFS_MAGIC
# define TMPFS_MAGIC 0x01021994
#endif

int
libcrun_get_cgroup_mode (libcrun_error_t *err)
{
  struct statfs stat;
  int ret;

  ret = statfs ("/sys/fs/cgroup", &stat);
  if (ret < 0)
    return crun_make_error (err, errno, "statfs '/sys/fs/cgroup'");
  if (stat.f_type == CGROUP2_SUPER_MAGIC)
    return CGROUP_MODE_UNIFIED;
  if (stat.f_type != TMPFS_MAGIC)
    return crun_make_error (err, errno, "invalid file system type on '/sys/fs/cgroup'");
  ret = statfs ("/sys/fs/cgroup/unified", &stat);
  if (ret < 0 && errno != ENOENT)
    return crun_make_error (err, errno, "statfs '/sys/fs/cgroup/unified'");
  if (ret < 0)
    return CGROUP_MODE_LEGACY;
  return stat.f_type == CGROUP2_SUPER_MAGIC ? CGROUP_MODE_HYBRID : CGROUP_MODE_LEGACY;
}

static int
enable_controllers (oci_container_linux_resources *resources, const char *path, libcrun_error_t *err)
{
  cleanup_free char *tmp_path = NULL;
  char *it;
  int ret;
  cleanup_free char *controllers = NULL;
  bool has_cpuset, has_cpu, has_io, has_memory, has_pids;

  has_cpu = resources && resources->cpu && (resources->cpu->shares || resources->cpu->period
                                            || resources->cpu->quota || resources->cpu->realtime_period
                                            || resources->cpu->realtime_runtime);
  has_cpuset = resources && resources->cpu && (resources->cpu->cpus || resources->cpu->mems);
  has_io = resources && resources->block_io;
  has_memory = resources && resources->memory;
  has_pids = resources && resources->pids;

  xasprintf (&controllers, "%s %s %s %s %s",
             has_cpu ? "+cpu" : "",
             has_io ? "+io" : "",
             has_memory ? "+memory" : "",
             has_pids ? "+pids" : "",
             has_cpuset ? "+cpuset" : "");

  xasprintf (&tmp_path, "%s/", path);

  for (it = strchr (tmp_path + 1, '/'); it;)
    {
      cleanup_free char *cgroup_path = NULL;
      cleanup_free char *subtree_control = NULL;
      char *next_slash = strchr (it + 1, '/');

      *it = '\0';

      xasprintf (&cgroup_path, "/sys/fs/cgroup%s", tmp_path);
      ret = mkdir (cgroup_path, 0755);
      if (ret < 0 && errno != EEXIST) {
        return crun_make_error (err, errno, "create '%s'", cgroup_path);
      }

      if (next_slash)
        {
          xasprintf (&subtree_control, "%s/cgroup.subtree_control", cgroup_path);
          ret = write_file (subtree_control, controllers, strlen (controllers), err);
          if (ret < 0)
            {
              int e = crun_error_get_errno (err);
              if (e == EPERM || e == EACCES || e == EBUSY)
                {
                  crun_error_release (err);
                  goto next;
                }
              return ret;
            }
        }
    next:
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
    return crun_make_error (err, errno, "open '%s'", path);

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
        return crun_make_error (err, errno, "read from 'memset.mems'");
      mems[b_len] = '\0';
      if (mems[0] == '\n')
        mems[0] = '\0';
    }

  /* look up in the parent directory.  */
  if (cpus[0] == '\0' || mems[0] == '\0')
    {
      size_t parent_path_len;
      int ret;

      for (parent_path_len = path_len -1; parent_path_len > 1 && path[parent_path_len] != '/'; parent_path_len--);
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
  const char *const files[] = {"memory.limit_in_bytes", "memory.kmem.limit_in_bytes", "memory.memsw.limit_in_bytes", NULL};
  cleanup_close int dirfd = -1;
  int i;

  dirfd = open (path, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open '%s'", path);

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

static int
enter_cgroup_subsystem (int cgroup_mode, pid_t pid, const char *subsystem, const char *path, int ensure_missing, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path_procs = NULL;
  cleanup_free char *cgroup_path = NULL;
  char pid_str[16];
  int ret;

  sprintf (pid_str, "%d", pid);

  xasprintf (&cgroup_path, "/sys/fs/cgroup/%s%s", subsystem, path ? path : "");
  if (ensure_missing)
    {
      ret = crun_ensure_directory (cgroup_path, 0755, err);
      if (UNLIKELY (ret < 0))
        {
          if (errno != EROFS)
            return crun_make_error (err, errno, "creating cgroup directory '%s'", cgroup_path);

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
      ret = crun_path_exists (cgroup_path, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 0)
        return 0;
    }

  xasprintf (&cgroup_path_procs, "/sys/fs/cgroup/%s%s/cgroup.procs", subsystem, path ? path : "");

  ret = write_file (cgroup_path_procs, pid_str, strlen (pid_str), err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
enter_cgroup (int cgroup_mode, pid_t pid, const char *path, int ensure_missing, libcrun_error_t *err)
{
  char pid_str[16];
  int ret;
  size_t i;
  int entered_any = 0;
  const cgroups_subsystem_t *subsystems;

  sprintf (pid_str, "%d", pid);

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      cleanup_free char *cgroup_path_procs = NULL;
      cleanup_free char *cgroup_path = NULL;

      xasprintf (&cgroup_path, "/sys/fs/cgroup/%s", path);
      if (ensure_missing)
        {
          ret = crun_ensure_directory (cgroup_path, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      xasprintf (&cgroup_path_procs, "/sys/fs/cgroup/%s/cgroup.procs", path);
      ret = write_file (cgroup_path_procs, pid_str, strlen (pid_str), err);
      if (UNLIKELY (ret < 0))
        return ret;
      return 0;
    }

  subsystems = libcrun_get_cgroups_subsystems (err);
  if (UNLIKELY (subsystems == NULL))
    return -1;

  for (i = 0; subsystems[i]; i++)
    {
      char subsystem_path[64];

      if (cgroup_mode == CGROUP_MODE_LEGACY && strcmp (subsystems[i], "unified") == 0)
        continue;

      sprintf (subsystem_path, "/sys/fs/cgroup/%s", subsystems[i]);
      ret = crun_path_exists (subsystem_path, !ensure_missing, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 0)
        continue;

      entered_any = 1;
      ret = enter_cgroup_subsystem (cgroup_mode, pid, subsystems[i], path, ensure_missing, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return entered_any ? 0 : -1;
}

int
libcrun_cgroups_create_symlinks (const char *target, libcrun_error_t *err)
{
  int i;
  cleanup_close int dirfd = open (target, O_DIRECTORY | O_RDONLY);

  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "cannot open /sys/fs/cgroup");

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
libcrun_move_process_to_cgroup (pid_t pid, char *path, libcrun_error_t *err)
{
  int cgroup_mode = libcrun_get_cgroup_mode (err);
  if (cgroup_mode < 0)
    return cgroup_mode;

  return enter_cgroup (cgroup_mode, pid, path, 0, err);
}

#ifdef HAVE_SYSTEMD
static
int systemd_finalize (oci_container_linux_resources *resources, int cgroup_mode, char **path, pid_t pid, const char *suffix, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  int ret;
  char *from, *to;
  char *saveptr = NULL;
  cleanup_free char *cgroup_path = NULL;

  xasprintf (&cgroup_path, "/proc/%d/cgroup", pid);
  ret = read_all_file (cgroup_path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (cgroup_mode == CGROUP_MODE_LEGACY)
    {
      from = strstr (content, "::memory");
      if (UNLIKELY (from == NULL))
        return crun_make_error (err, -1, "cannot find memory controller for the current process");

      from += 8;
      to = strchr (from, '\n');
      if (UNLIKELY (to == NULL))
        return crun_make_error (err, -1, "cannot parse /proc/self/cgroup");
      *to = '\0';
      if (suffix)
        xasprintf (path, "%s/%s", from, suffix);
      else
        *path = xstrdup (from);
      *to = '\n';
    }
  else
    {
      from = strstr (content, "0::");
      if (UNLIKELY (from == NULL))
        return crun_make_error (err, -1, "cannot find cgroup2 for the current process");

      from += 3;
      to = strchr (from, '\n');
      if (UNLIKELY (to == NULL))
        return crun_make_error (err, -1, "cannot parse /proc/self/cgroup");
      *to = '\0';
      if (suffix)
        xasprintf (path, "%s/%s", from, suffix);
      else
        *path = xstrdup (from);
      *to = '\n';
    }

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      ret = enable_controllers (resources, *path, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (cgroup_mode != CGROUP_MODE_UNIFIED && geteuid ())
    return 0;

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      char *subpath, *subsystem;
      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      if (strcmp (subpath, *path))
        {
          ret = enter_cgroup_subsystem (cgroup_mode, pid, subsystem, *path, 1, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  return 0;
}

struct systemd_job_removed_s
{
  const char *path;
  int *terminated;
};

static int
systemd_job_removed (sd_bus_message *m, void *userdata, sd_bus_error *error)
{
  const char *path, *unit, *result;
  uint32_t id;
  int ret;
  struct systemd_job_removed_s *p = userdata;

  ret = sd_bus_message_read (m, "uoss", &id, &path, &unit, &result);
  if (ret < 0)
    return -1;

  if (strcmp (p->path, path) == 0)
    *p->terminated = 1;
  return 0;
}

static
int enter_systemd_cgroup_scope (oci_container_linux_resources *resources, const char *id, const char *slice, pid_t pid, libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int sd_err, ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object;
  int terminated = 0;
  struct systemd_job_removed_s userdata;
  int i;
  const char *boolean_opts[10];
  cleanup_free char *scope = NULL;

  i = 0;
  boolean_opts[i++] = "Delegate";
  if (resources)
    {
      if (resources->cpu)
        boolean_opts[i++] = "CPUAccounting";
      if (resources->memory)
        boolean_opts[i++] = "MemoryAccounting";
      if (resources->block_io)
        boolean_opts[i++] = "IOAccounting";
      if (resources->pids)
        boolean_opts[i++] = "TasksAccounting";
    }
  boolean_opts[i++] = NULL;

  sd_err = sd_bus_default (&bus);
  if (sd_err < 0)
    {
      sd_err = sd_bus_default_system (&bus);
      if (sd_err < 0)
        {
          crun_make_error (err, -sd_err, "cannot open sd-bus");
          ret = -1;
          goto exit;
        }
    }

  sd_err = sd_bus_add_match (bus,
                          NULL,
                          "type='signal',"
                          "sender='org.freedesktop.systemd1',"
                          "interface='org.freedesktop.systemd1.Manager',"
                          "member='JobRemoved',"
                          "path='/org/freedesktop/systemd1'",
                          systemd_job_removed, &userdata);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus add match");
      goto exit;
    }

  sd_err = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartTransientUnit");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "set up dbus message");
      goto exit;
    }

  if (slice == NULL || slice[0] == '\0')
      xasprintf (&scope, "%s-%d.scope", id, getpid ());
  else
    {
      char *n = strchr (slice, ':');
      if (n == NULL)
        xasprintf (&scope, "%s.scope", slice);
      else
        {
          xasprintf (&scope, "%s.scope", n + 1);
          n = strchr (scope, ':');
          if (n)
            *n = '-';
        }
    }

  sd_err = sd_bus_message_append (m, "ss", scope, "fail");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  sd_err = sd_bus_message_open_container (m, 'a', "(sv)");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus open container");
      goto exit;
    }

  if (slice && slice[0])
    {
      cleanup_free char *slice_name = xstrdup (slice);
      char *endptr = strchr (slice_name, ':');

      if (endptr)
        *endptr = '\0';

      sd_err = sd_bus_message_append (m, "(sv)", "Slice", "s", slice_name);
      if (UNLIKELY (sd_err < 0))
        {
          ret = crun_make_error (err, -sd_err, "sd-bus message append");
          goto exit;
        }
    }

  sd_err = sd_bus_message_append (m, "(sv)", "Description", "s", "libcrun container");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "(sv)", "PIDs", "au", 1, pid);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  for (i = 0; boolean_opts[i]; i++)
    {
      sd_err = sd_bus_message_append (m, "(sv)", boolean_opts[i], "b", 1);
      if (UNLIKELY (sd_err < 0))
        {
          ret = crun_make_error (err, -sd_err, "sd-bus message append");
          goto exit;
        }
    }

  sd_err = sd_bus_message_close_container (m);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus close container");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "a(sa(sv))", 0);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  sd_err = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call");
      goto exit;
    }

  sd_err = sd_bus_message_read (reply, "o", &object);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message read");
      goto exit;
    }

  userdata.path = object;
  userdata.terminated = &terminated;
  while (!terminated)
    {
      sd_err = sd_bus_process (bus, NULL);
      if (UNLIKELY (sd_err < 0))
        {
          ret = crun_make_error (err, -sd_err, "sd-bus process");
          break;
        }

      if (sd_err == 0)
        {
          sd_err = sd_bus_wait (bus, (uint64_t) -1);
          if (UNLIKELY (sd_err < 0))
            {
              ret = crun_make_error (err, -sd_err, "sd-bus wait");
              break;
            }
          continue;
        }
    }

exit:
  if (bus)
    sd_bus_unref (bus);
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);
  return ret;
}

static
int destroy_systemd_cgroup_scope (const char *scope, libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object;
  int terminated = 0;
  struct systemd_job_removed_s userdata;

  if (sd_bus_default (&bus) < 0)
    {
      ret = crun_make_error (err, 0, "cannot open sd-bus");
      goto exit;
    }

  ret = sd_bus_add_match (bus,
                          NULL,
                          "type='signal',"
                          "sender='org.freedesktop.systemd1',"
                          "interface='org.freedesktop.systemd1.Manager',"
                          "member='JobRemoved',"
                          "path='/org/freedesktop/systemd1'",
                          systemd_job_removed, &userdata);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message read");
      goto exit;
    }

  if (UNLIKELY (sd_bus_message_new_method_call (bus, &m,
                                                "org.freedesktop.systemd1",
                                                "/org/freedesktop/systemd1",
                                                "org.freedesktop.systemd1.Manager",
                                                "StopUnit") < 0))
    {
      ret = crun_make_error (err, 0, "set up dbus message");
      goto exit;
    }

  if (UNLIKELY (sd_bus_message_append (m, "ss", scope, "replace") < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message append");
      goto exit;
    }

  ret = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call");
      goto exit;
    }
  ret = sd_bus_message_read (reply, "o", &object);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message read");
      goto exit;
    }

  userdata.path = object;
  userdata.terminated = &terminated;
  while (!terminated)
    {
      ret = sd_bus_process (bus, NULL);
      if (UNLIKELY (ret < 0))
        {
          ret = crun_make_error (err, 0, "sd-bus process");
          break;
        }

      if (ret == 0)
        {
          ret = sd_bus_wait (bus, (uint64_t) -1);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, 0, "sd-bus wait");
              break;
            }
          continue;
        }

      if (UNLIKELY (ret < 0))
        {
          ret = crun_make_error (err, 0, "sd-bus wait");
          break;
        }
    }
exit:
  if (bus)
    sd_bus_unref (bus);
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);
  return ret;
}

#endif

static int
libcrun_cgroup_enter_internal (oci_container_linux_resources *resources, int cgroup_mode, char **path, const char *cgroup_path, int manager, pid_t pid, const char *id, libcrun_error_t *err)
{
  if (manager == CGROUP_MANAGER_DISABLED)
    {
      *path = NULL;
      return 0;
    }

#ifdef HAVE_SYSTEMD
  if (manager == CGROUP_MANAGER_SYSTEMD)
    {
      int ret;

      ret = enter_systemd_cgroup_scope (resources, id, cgroup_path, pid, err);
      if (UNLIKELY (ret < 0))
        return ret;

      return systemd_finalize (resources, cgroup_mode, path, pid, NULL, err);
    }
#endif

  if (cgroup_path == NULL)
      xasprintf (path, "/%s", id);
  else
    {
      if (cgroup_path[0] == '/')
        *path = xstrdup (cgroup_path);
      else
        xasprintf (path, "/%s", cgroup_path);
    }

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      int ret;

      ret = enable_controllers (resources, *path, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return enter_cgroup (cgroup_mode, pid, *path, 1, err);
}

static int
is_rootless (libcrun_error_t *err)
{
  if (geteuid ())
    return 1;

  return check_running_in_user_namespace (err);
}

int
libcrun_cgroup_enter (oci_container_linux_resources *resources, int cgroup_mode, char **path, const char *cgroup_path, int manager, pid_t pid, const char *id, libcrun_error_t *err)
{
  libcrun_error_t tmp_err = NULL;
  int rootless;
  int ret;

  if (cgroup_mode == CGROUP_MODE_HYBRID)
    {
      /* We don't really support hybrid mode, so check that cgroups2 is not using any controller.  */

      size_t len;
      cleanup_free char *buffer = NULL;

      ret = read_all_file ("/sys/fs/cgroup/unified/cgroup.controllers", &buffer, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (len > 0)
        return crun_make_error (err, errno, "cgroups in hybrid mode not supported, drop all controllers from cgroupv2");
    }

  ret = libcrun_cgroup_enter_internal (resources, cgroup_mode, path, cgroup_path, manager, pid, id, err);
  if (LIKELY (ret == 0))
    return ret;

  rootless = is_rootless (&tmp_err);
  if (UNLIKELY (rootless < 0))
    {
      crun_error_release (err);
      *err = tmp_err;
      return ret;
    }

  if (rootless > 0 && cgroup_mode != CGROUP_MODE_UNIFIED)
    {
      free (*path);
      *path = NULL;
      crun_error_release (err);
      return 0;
    }

  return ret;
}

int
libcrun_cgroup_killall (char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path_procs = NULL;
  cleanup_free char *buffer = NULL;
  int ret;
  size_t len;
  char *it;
  char *saveptr = NULL;
  int mode;

  if (path == NULL || *path == '\0')
    return 0;

  mode = libcrun_get_cgroup_mode (err);
  if (mode < 0)
    return mode;

  switch (mode)
    {
    case CGROUP_MODE_UNIFIED:
      xasprintf (&cgroup_path_procs, "/sys/fs/cgroup/%s/cgroup.procs", path);
      ret = read_all_file (cgroup_path_procs, &buffer, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      break;

    case CGROUP_MODE_HYBRID:
    case CGROUP_MODE_LEGACY:
      xasprintf (&cgroup_path_procs, "/sys/fs/cgroup/pids/%s/cgroup.procs", path);
      ret = read_all_file (cgroup_path_procs, &buffer, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      break;
    }
  for (it = strtok_r (buffer, "\n", &saveptr); it; it = strtok_r (NULL, "\n", &saveptr))
    {
      pid_t pid = strtoul (it, NULL, 10);
      if (pid > 0)
        {
          ret = kill (pid, SIGKILL);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "kill process %d", pid);
        }
    }

  return 0;
}

int
libcrun_cgroup_destroy (const char *id, char *path, int systemd_cgroup, libcrun_error_t *err)
{
  int ret;
  size_t i;
  ssize_t path_len;
  int mode;
  const cgroups_subsystem_t *subsystems;

  if (path == NULL || *path == '\0')
    return 0;

  subsystems = libcrun_get_cgroups_subsystems (err);
  if (UNLIKELY (subsystems == NULL))
    return -1;

  mode = libcrun_get_cgroup_mode (err);
  if (mode < 0)
    return mode;

#ifdef HAVE_SYSTEMD
  if (systemd_cgroup)
    {
      ret = destroy_systemd_cgroup_scope (id, err);
      if (UNLIKELY (ret < 0))
        crun_error_release (err);
    }
#endif

  ret = libcrun_cgroup_killall (path, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  path_len = strlen (path);
  while (1)
    {
      if (mode == CGROUP_MODE_UNIFIED)
        {
          cleanup_free char *cgroup_path = NULL;

          xasprintf (&cgroup_path, "/sys/fs/cgroup/%s", path);
          if (rmdir (cgroup_path) < 0)
            break;
        }
      else
        {
          bool cleaned_any = false;

          for (i = 0; subsystems[i]; i++)
            {
              cleanup_free char *cgroup_path = NULL;

              if (mode == CGROUP_MODE_LEGACY && strcmp (subsystems[i], "unified") == 0)
                continue;

              xasprintf (&cgroup_path, "/sys/fs/cgroup/%s/%s", subsystems[i], path);

              if (rmdir (cgroup_path) == 0)
                cleaned_any = true;
            }

          if (!cleaned_any)
            break;
        }

      if (path_len <= 1)
       break;

      for (; path_len > 1 && path[path_len] != '/'; path_len--);
      if (path_len > 1)
       path[path_len] = '\0';
   }

  return 0;
}

/* The parser generates different structs but they are really all the same.  */
struct throttling_s
{
    int64_t major;
    int64_t minor;
    uint64_t rate;
};

static int
write_blkio_v1_resources_throttling (int dirfd, const char *name, struct throttling_s **throttling, size_t throttling_len, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  cleanup_close int fd = -1;

  if (throttling == NULL)
    return 0;

  fd = openat (dirfd, name, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open %s", name);

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 "%" PRIu64 "\n",
                     throttling[i]->major,
                     throttling[i]->minor,
                     throttling[i]->rate);

      ret = write (fd, fmt_buf, len);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write %s", name);
    }
  return 0;
}

static int
write_blkio_v2_resources_throttling (int fd, const char *name, struct throttling_s **throttling, size_t throttling_len, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;

  if (throttling == NULL)
    return 0;

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %s=%lu\n",
                     throttling[i]->major,
                     throttling[i]->minor,
                     name,
                     throttling[i]->rate);

      ret = write (fd, fmt_buf, len);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write %s", name);
    }
  return 0;
}

static int
write_blkio_resources (int dirfd, bool cgroup2, oci_container_linux_resources_block_io *blkio, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
      /* convert linearly from 10-1000 to 1-10000.  */
#define CONVERT_WEIGHT_TO_CGROUPS_V2(x) (1 + ((x) - 10) * 9999 / 990)

  if (blkio->weight)
    {
      uint32_t val = blkio->weight;

      if (cgroup2)
        val = CONVERT_WEIGHT_TO_CGROUPS_V2 (val);

      len = sprintf (fmt_buf, "%" PRIu32, val);
      ret = write_file_at (dirfd, cgroup2 ? "io.weight" : "blkio.weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->leaf_weight)
    {
      if (cgroup2)
        return crun_make_error (err, errno, "cannot set leaf_weight with cgroupv2");
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

          wfd = openat (dirfd, "io.weight", O_WRONLY);
          if (UNLIKELY (wfd < 0))
            return crun_make_error (err, errno, "open io.weight");
          for (i = 0; i < blkio->weight_device_len; i++)
            {
              uint32_t w = CONVERT_WEIGHT_TO_CGROUPS_V2 (blkio->weight_device[i]->weight);

              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %i\n",
                             blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor,
                             w);
              ret = write (wfd, fmt_buf, len);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write io.weight");

              /* Ignore blkio->weight_device[i]->leaf_weight.  */
            }
        }
      else
        {
          cleanup_close int w_device_fd = -1;
          cleanup_close int w_leafdevice_fd = -1;
          int i;

          w_device_fd = openat (dirfd, "blkio.weight_device", O_WRONLY);
          if (UNLIKELY (w_device_fd < 0))
            return crun_make_error (err, errno, "open blkio.weight_device");

          w_leafdevice_fd = openat (dirfd, "blkio.leaf_weight_device", O_WRONLY);
          if (UNLIKELY (w_leafdevice_fd < 0))
            return crun_make_error (err, errno, "open blkio.leaf_weight_device");

          for (i = 0; i < blkio->weight_device_len; i++)
            {
              len = sprintf (fmt_buf, "%lu:%lu %i\n",
                             blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor,
                             blkio->weight_device[i]->weight);
              ret = write (w_device_fd, fmt_buf, len);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.weight_device");

              len = sprintf (fmt_buf, "%lu:%lu %i\n",
                             blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor,
                             blkio->weight_device[i]->leaf_weight);
              ret = write (w_leafdevice_fd, fmt_buf, len);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.leaf_weight_device");
            }
        }
    }
  if (cgroup2)
    {
      cleanup_close int wfd = -1;

      wfd = openat (dirfd, "io.max", O_WRONLY);
      if (UNLIKELY (wfd < 0))
        return crun_make_error (err, errno, "open io.max");

      ret = write_blkio_v2_resources_throttling (wfd, "rbps",
                                                 (struct throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wbps",
                                                 (struct throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "riops",
                                                 (struct throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wiops",
                                                 (struct throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_bps_device",
                                                 (struct throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_bps_device",
                                                 (struct throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_iops_device",
                                                 (struct throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_iops_device",
                                                 (struct throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len,
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_network_resources (int dirfd, oci_container_linux_resources_network *net, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
  if (net->class_id)
    {
      len = sprintf (fmt_buf, "%d", net->class_id);
      ret = write_file_at (dirfd, "net_cls.classid", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (net->priorities_len)
    {
      size_t i;
      cleanup_close int fd = -1;
      fd = openat (dirfd, "net_prio.ifpriomap", O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open net_prio.ifpriomap");

      for (i = 0; i < net->priorities_len; i++)
        {
          len = sprintf (fmt_buf, "%s %d\n", net->priorities[i]->name, net->priorities[i]->priority);
          ret = write (fd, fmt_buf, len);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write net_prio.ifpriomap");
        }

    }

  return 0;
}

static int
write_hugetlb_resources (int dirfd, oci_container_linux_resources_hugepage_limits_element **htlb, size_t htlb_len, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  for (i = 0; i < htlb_len; i++)
    {
      cleanup_free char *filename = NULL;
      size_t len;
      int ret;

      xasprintf (&filename, "hugetlb.%s.limit_in_bytes", htlb[i]->page_size);

      len = sprintf (fmt_buf, "%lu", htlb[i]->limit);
      ret = write_file_at (dirfd, filename, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}


static int
write_devices_resources_v1 (int dirfd, oci_container_linux_resources_devices_element **devs, size_t devs_len, libcrun_error_t *err)
{
  size_t i, len;
  int ret;
  char *default_devices[] =
    {
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

#define FMT_DEV(x, b)                           \
          {                                     \
            if (x ## _present)                  \
              sprintf (b, "%lu", x);            \
            else                                \
              strcpy (b, "*");                  \
          } while(0)                            \

          FMT_DEV (devs[i]->major, fmt_buf_major);
          FMT_DEV (devs[i]->minor, fmt_buf_minor);

          len = snprintf (fmt_buf, FMT_BUF_LEN - 1, "%s %s:%s %s", devs[i]->type, fmt_buf_major, fmt_buf_minor, devs[i]->access);
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
write_devices_resources_v2_internal (int dirfd, oci_container_linux_resources_devices_element **devs, size_t devs_len, libcrun_error_t *err)
{
  int i, ret;
  cleanup_free struct bpf_program *program = NULL;
  struct default_dev_s {
    char type;
    int major;
    int minor;
    const char *access;
  };
  struct default_dev_s default_devices[] =
    {
     {'c', -1, -1, "m"},
     {'b', -1, -1, "m"},
     {'c', 1, 3, "rwm"},
     {'c', 1, 8, "rwm"},
     {'c', 1, 7, "rwm"},
     {'c', 5, 0, "rwm"},
     {'c', 1, 5, "rwm"},
     {'c', 1, 9, "rwm"},
     {'c', 5, 1, "rwm"},
     {'c', 136, -1, "rwm"},
     {'c', 5, 2, "rwm"},
     {'c', 10, 200, "rwm"},
  };

  program = bpf_program_new (2048);

  program = bpf_program_init_dev (program, err);
  if (UNLIKELY (program == NULL))
    return -1;

  for (i = (sizeof (default_devices) / sizeof (default_devices[0])) - 1; i >= 0 ; i--)
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
write_devices_resources_v2 (int dirfd, oci_container_linux_resources_devices_element **devs, size_t devs_len, libcrun_error_t *err)
{
  int ret, i;
  bool can_skip = true;

  ret = write_devices_resources_v2_internal (dirfd, devs, devs_len, err);
  if (LIKELY (ret == 0))
    return 0;

  /* If writing the resources ebpf failed, check if it is fine to ignore the error.  */
  for (i = 0; i < devs_len; i++)
    {
      if (devs[i]->allow || strcmp (devs[i]->access, "rwm"))
        {
          can_skip = false;
          break;
        }
    }

  if (can_skip)
    {
      crun_error_release (err);
      ret = 0;
    }

  return ret;
}


static int
write_devices_resources (int dirfd, bool cgroup2, oci_container_linux_resources_devices_element **devs, size_t devs_len, libcrun_error_t *err)
{
  if (cgroup2)
    return write_devices_resources_v2 (dirfd, devs, devs_len, err);

  return write_devices_resources_v1 (dirfd, devs, devs_len, err);
}

static int
write_memory_resources (int dirfd, bool cgroup2, oci_container_linux_resources_memory *memory, libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[32];
  char swap_buf[32];
  char limit_buf[32];
  size_t swap_buf_len, limit_buf_len;
  swap_buf_len = sprintf (swap_buf, "%lu", memory->swap);
  limit_buf_len = sprintf (limit_buf, "%lu", memory->limit);

  if (memory->limit)
    {
      ret = write_file_at (dirfd, cgroup2 ? "memory.max" : "memory.limit_in_bytes", limit_buf, limit_buf_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->swap)
    {
      ret = write_file_at (dirfd, cgroup2 ? "memory.swap.max" : "memory.memsw.limit_in_bytes", swap_buf, swap_buf_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->kernel)
    {
      if (cgroup2)
        return crun_make_error (err, errno, "cannot set kernel memory with cgroupv2");

      len = sprintf (fmt_buf, "%lu", memory->kernel);
      ret = write_file_at (dirfd, "memory.kmem.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->reservation)
    {
      len = sprintf (fmt_buf, "%lu", memory->reservation);
      ret = write_file_at (dirfd, cgroup2 ? "memory.high" : "memory.soft_limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->disable_oom_killer)
    {
      if (cgroup2)
        return crun_make_error (err, errno, "cannot disable OOM killer with cgroupv2");

      ret = write_file_at (dirfd, "memory.oom_control", "1", 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->kernel_tcp)
    {
      if (cgroup2)
        return crun_make_error (err, errno, "cannot set kernel TCP with cgroupv2");

      len = sprintf (fmt_buf, "%lu", memory->kernel_tcp);
      ret = write_file_at (dirfd, "memory.kmem.tcp.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->swappiness && memory->swappiness <= 100)
    {
      if (cgroup2)
        return crun_make_error (err, errno, "cannot set memory swappiness with cgroupv2");

      len = sprintf (fmt_buf, "%lu", memory->swappiness);
      ret = write_file_at (dirfd, "memory.swappiness", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_pids_resources (int dirfd, bool cgroup2, oci_container_linux_resources_pids *pids, libcrun_error_t *err)
{
  if (pids->limit)
    {
      char fmt_buf[32];
      size_t len;
      int ret;

      len = sprintf (fmt_buf, "%lu", pids->limit);
      ret = write_file_at (dirfd, "pids.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_cpu_resources (int dirfd_cpu, bool cgroup2, oci_container_linux_resources_cpu *cpu, libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[64];
  int64_t period = -1;
  int64_t quota = -1;

      /* convert linearly from 2-262144 to 1-10000.  */
#define CONVERT_SHARES_TO_CGROUPS_V2(x) (1 + (((x) - 2) * 9999) / 262142)

  if (cpu->shares)
    {
      uint32_t val = cpu->shares;

      if (cgroup2)
        val = CONVERT_SHARES_TO_CGROUPS_V2 (val);

      len = sprintf (fmt_buf, "%u", val);

      ret = write_file_at (dirfd_cpu, cgroup2 ? "cpu.weight" : "cpu.shares", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->period)
    {
      if (cgroup2)
        period = cpu->period;
      else
        {
          len = sprintf (fmt_buf, "%lu", cpu->period);
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
          len = sprintf (fmt_buf, "%lu", cpu->quota);
          ret = write_file_at (dirfd_cpu, "cpu.cfs_quota_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (cpu->realtime_period)
    {
      if (cgroup2)
        return crun_make_error (err, errno, "realtime period not supported on cgroupv2");
      len = sprintf (fmt_buf, "%lu", cpu->realtime_period);
      ret = write_file_at (dirfd_cpu, "cpu.rt_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->realtime_runtime)
    {
      if (cgroup2)
        return crun_make_error (err, errno, "realtime runtime not supported on cgroupv2");
      len = sprintf (fmt_buf, "%lu", cpu->realtime_runtime);
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
      ret = write_file_at (dirfd_cpu, "cpu.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_cpuset_resources (int dirfd_cpuset, int cgroup2, oci_container_linux_resources_cpu *cpu, libcrun_error_t *err)
{
  int ret;

  if (cpu->cpus)
    {
      ret = write_file_at (dirfd_cpuset, "cpuset.cpus", cpu->cpus, strlen (cpu->cpus), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->mems)
    {
      ret = write_file_at (dirfd_cpuset, "cpuset.mems", cpu->mems, strlen (cpu->mems), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
update_cgroup_v1_resources (oci_container_linux_resources *resources, char *path, libcrun_error_t *err)
{
  int ret;

  if (resources->block_io)
    {
      cleanup_free char *path_to_blkio = NULL;
      cleanup_close int dirfd_blkio = -1;
      oci_container_linux_resources_block_io *blkio = resources->block_io;

      xasprintf (&path_to_blkio, "/sys/fs/cgroup/blkio%s/", path);
      dirfd_blkio = open (path_to_blkio, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_blkio < 0))
        return crun_make_error (err, errno, "open %s", path_to_blkio);

      ret = write_blkio_resources (dirfd_blkio, false, blkio, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->network)
    {
      cleanup_free char *path_to_network = NULL;
      cleanup_close int dirfd_network = -1;
      oci_container_linux_resources_network *network = resources->network;

      xasprintf (&path_to_network, "/sys/fs/cgroup/net_cls,net_prio%s/", path);
      dirfd_network = open (path_to_network, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_network < 0))
        return crun_make_error (err, errno, "open %s", path_to_network);

      ret = write_network_resources (dirfd_network, network, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->hugepage_limits_len)
    {
      cleanup_free char *path_to_htlb = NULL;
      cleanup_close int dirfd_htlb = -1;

      xasprintf (&path_to_htlb, "/sys/fs/cgroup/hugetlb%s/", path);
      dirfd_htlb = open (path_to_htlb, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_htlb < 0))
        return crun_make_error (err, errno, "open %s", path_to_htlb);

      ret = write_hugetlb_resources (dirfd_htlb,
                                     resources->hugepage_limits,
                                     resources->hugepage_limits_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->devices_len)
    {
      cleanup_free char *path_to_devs = NULL;
      cleanup_close int dirfd_devs = -1;

      xasprintf (&path_to_devs, "/sys/fs/cgroup/devices%s/", path);
      dirfd_devs = open (path_to_devs, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_devs < 0))
        return crun_make_error (err, errno, "open %s", path_to_devs);

      ret = write_devices_resources (dirfd_devs, false,
                                     resources->devices,
                                     resources->devices_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      cleanup_free char *path_to_mem = NULL;
      cleanup_close int dirfd_mem = -1;

      xasprintf (&path_to_mem, "/sys/fs/cgroup/memory%s/", path);
      dirfd_mem = open (path_to_mem, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_mem < 0))
        return crun_make_error (err, errno, "open %s", path_to_mem);

      ret = write_memory_resources (dirfd_mem, false,
                                    resources->memory,
                                    err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->pids)
    {
      cleanup_free char *path_to_pid = NULL;
      cleanup_close int dirfd_pid = -1;

      xasprintf (&path_to_pid, "/sys/fs/cgroup/pids%s/", path);
      dirfd_pid = open (path_to_pid, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_pid < 0))
        return crun_make_error (err, errno, "open %s", path_to_pid);

      ret = write_pids_resources (dirfd_pid, false,
                                  resources->pids,
                                  err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->cpu)
    {
      cleanup_free char *path_to_cpu = NULL;
      cleanup_close int dirfd_cpu = -1;
      cleanup_free char *path_to_cpuset = NULL;
      cleanup_close int dirfd_cpuset = -1;

      xasprintf (&path_to_cpu, "/sys/fs/cgroup/cpu%s/", path);
      dirfd_cpu = open (path_to_cpu, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpu < 0))
        return crun_make_error (err, errno, "open %s", path_to_cpu);
      ret = write_cpu_resources (dirfd_cpu, false,
                                 resources->cpu,
                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (resources->cpu->cpus == NULL && resources->cpu->mems == NULL)
        return 0;

      xasprintf (&path_to_cpuset, "/sys/fs/cgroup/cpuset%s/", path);
      dirfd_cpuset = open (path_to_cpuset, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpuset < 0))
        return crun_make_error (err, errno, "open %s", path_to_cpuset);
      ret = write_cpuset_resources (dirfd_cpuset, false,
                                    resources->cpu,
                                    err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
update_cgroup_v2_resources (oci_container_linux_resources *resources, char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int cgroup_dirfd = -1;
  int ret;

  if (resources->network)
    return crun_make_error (err, errno, "network limits not supported on cgroupv2");
  if (resources->hugepage_limits_len)
    return crun_make_error (err, errno, "hugepages not supported on cgroupv2");

  xasprintf (&cgroup_path, "/sys/fs/cgroup%s", path);

  cgroup_dirfd = open (cgroup_path, O_DIRECTORY);
  if (UNLIKELY (cgroup_dirfd < 0))
    return crun_make_error (err, errno, "open %s", cgroup_path);

  if (resources->devices_len)
    {
      ret = write_devices_resources (cgroup_dirfd, true,
                                     resources->devices,
                                     resources->devices_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      ret = write_memory_resources (cgroup_dirfd, true,
                                    resources->memory,
                                    err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->pids)
    {
      ret = write_pids_resources (cgroup_dirfd, true,
                                  resources->pids,
                                  err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->cpu)
    {
      ret = write_cpu_resources (cgroup_dirfd, true,
                                 resources->cpu,
                                 err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_cpuset_resources (cgroup_dirfd, true,
                                    resources->cpu,
                                    err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->block_io)
    {
      ret = write_blkio_resources (cgroup_dirfd, true, resources->block_io, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

int
libcrun_update_cgroup_resources (int cgroup_mode, oci_container_linux_resources *resources, char *path, libcrun_error_t *err)
{
  if (path == NULL)
    {
      size_t i;

      if (resources->block_io
          || resources->network
          || resources->hugepage_limits_len
          || resources->memory
          || resources->pids
          || resources->cpu)
        return crun_make_error (err, errno, "cannot set limits without cgroups");

      for (i = 0; i < resources->devices_len; i++)
        {
          if (resources->devices[i]->allow || strcmp (resources->devices[i]->access, "rwm"))
            return crun_make_error (err, errno, "cannot set limits without cgroups");
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
      return crun_make_error (err, 0, "invalid cgroup mode");
    }
}
