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
#include "linux.h"
#include "utils.h"
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <signal.h>
#include "terminal.h"
#include "cgroup.h"
#include "status.h"
#include <sys/socket.h>
#include <libgen.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/personality.h>

#ifndef RLIMIT_RTTIME
# define RLIMIT_RTTIME 15
#endif

/* Defined in chroot_realpath.c  */
char *chroot_realpath (const char *chroot, const char *path, char resolved_path[]);

struct remount_s
{
  struct remount_s *next;
  char *target;
  unsigned long flags;
  char *data;
};

struct private_data_s
{
  struct remount_s *remounts;

  /* Filled by libcrun_run_linux_container().  Useful to query what
     namespaces are available.  */
  int unshare_flags;

  char *host_notify_socket_path;
  char *container_notify_socket_path;
  bool mount_dev_from_host;
  unsigned long rootfs_propagation;
  bool deny_setgroups;
};

struct linux_namespace_s
{
  const char *name;
  int value;
};

static struct private_data_s *
get_private_data (struct libcrun_container_s *container)
{
  if (container->private_data == NULL)
    {
      struct private_data_s *p = xmalloc (sizeof (*p));
      memset (p, 0, sizeof (*p));
      container->private_data = p;
    }
  return container->private_data;
}

static struct linux_namespace_s namespaces[] =
  {
    {"mount", CLONE_NEWNS},
    {"network", CLONE_NEWNET},
    {"ipc", CLONE_NEWIPC},
    {"pid", CLONE_NEWPID},
    {"uts", CLONE_NEWUTS},
    {"user", CLONE_NEWUSER},
#ifdef CLONE_NEWCGROUP
    {"cgroup", CLONE_NEWCGROUP},
#endif
    {NULL, 0}
  };

static int
find_namespace (const char *name)
{
  struct linux_namespace_s *it;
  for (it = namespaces; it->name; it++)
    if (strcmp (it->name, name) == 0)
      return it->value;
  return -1;
}

static int
syscall_clone (unsigned long flags, void *child_stack)
{
  return (int) syscall (__NR_clone, flags, child_stack);
}

static int
syscall_keyctl_join (const char *name)
{
#define KEYCTL_JOIN_SESSION_KEYRING 0x1
  return (int) syscall (__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, name, 0);
}

int
libcrun_create_keyring (const char *name, libcrun_error_t *err)
{
  int ret = syscall_keyctl_join (name);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "create keyring '%s'", name);
  return 0;
}

static void
get_uid_gid_from_def (oci_container *def, uid_t *uid, gid_t *gid)
{
  *uid = 0;
  *gid = 0;

  if (def->process && def->process->user)
    {
      if (def->process->user->uid)
        *uid = def->process->user->uid;
      if (def->process->user->gid)
        *gid = def->process->user->gid;
    }
}

struct propagation_flags_s
  {
    const char *name;
    int clear;
    int flags;
    int extra_flags;
  };

enum {
      OPTION_TMPCOPYUP = 1
};

static struct propagation_flags_s propagation_flags[] =
  {
   {"defaults", 0, 0, 0},
   {"rbind", 0, MS_REC | MS_BIND, 0},
   {"ro", 0, MS_RDONLY, 0},
   {"rw", 1, MS_RDONLY, 0},
   {"suid", 1, MS_NOSUID, 0},
   {"nosuid", 0, MS_NOSUID, 0},
   {"dev", 1, MS_NODEV, 0},
   {"nodev", 0, MS_NODEV, 0},
   {"exec", 1, MS_NOEXEC, 0},
   {"noexec", 0, MS_NOEXEC, 0},
   {"sync", 0, MS_SYNCHRONOUS, 0},
   {"async", 1, MS_SYNCHRONOUS, 0},
   {"dirsync", 0, MS_DIRSYNC, 0},
   {"remount", 0, MS_REMOUNT, 0},
   {"mand", 0, MS_MANDLOCK, 0},
   {"nomand", 1, MS_MANDLOCK, 0},
   {"atime", 1, MS_NOATIME, 0},
   {"noatime", 0, MS_NOATIME, 0},
   {"diratime", 1, MS_NODIRATIME, 0},
   {"nodiratime", 0, MS_NODIRATIME, 0},
   {"relatime", 0, MS_RELATIME, 0},
   {"norelatime", 1, MS_RELATIME, 0},
   {"strictatime", 0, MS_STRICTATIME, 0},
   {"nostrictatime", 1, MS_STRICTATIME, 0},
   {"shared", 0, MS_SHARED, 0},
   {"rshared", 0, MS_REC | MS_SHARED, 0},
   {"slave", 0, MS_SLAVE, 0},
   {"rslave", 0, MS_REC | MS_SLAVE, 0},
   {"private", 0, MS_PRIVATE, 0},
   {"rprivate", 0, MS_REC | MS_PRIVATE, 0},
   {"unbindable", 0, MS_UNBINDABLE, 0},
   {"runbindable", 0, MS_REC | MS_UNBINDABLE, 0},

   {"tmpcopyup", 0, 0, OPTION_TMPCOPYUP},

   {NULL, 0, 0, 0}
  };

static unsigned long
get_mount_flags (const char *name, int current_flags, int *found, unsigned long *extra_flags)
{
  struct propagation_flags_s *it;
  if (found)
    *found = 0;
  for (it = propagation_flags; it->name; it++)
    if (strcmp (it->name, name) == 0)
      {
        if (found)
          *found = 1;

        if (extra_flags)
          *extra_flags |= it->extra_flags;

        if (it->clear)
          return current_flags & ~it->flags;

        return current_flags | it->flags;
      }
  return 0;
}

static unsigned long
get_mount_flags_or_option (const char *name, int current_flags, unsigned long *extra_flags, char **option)
{
  int found;
  cleanup_free char *prev = NULL;
  unsigned long flags = get_mount_flags (name, current_flags, &found, extra_flags);
  if (found)
    return flags;

  prev = *option;
  if (*option && **option)
    xasprintf (option, "%s,%s", *option, name);
  else
    *option = xstrdup (name);

  return 0;
}

int
pivot_root (const char * new_root, const char * put_old)
{
  return syscall (__NR_pivot_root, new_root, put_old);
}

static void
free_remount (struct remount_s *r)
{
  free (r->data);
  free (r->target);
  free (r);
}

static struct remount_s *
make_remount (const char *target, unsigned long flags, const char *data, struct remount_s *next)
{
  struct remount_s *ret = xmalloc (sizeof (*ret));
  ret->target = xstrdup (target);
  ret->flags = flags;
  ret->data = data ? xstrdup (data) : NULL;
  ret->next = next;
  return ret;
}

static int
do_remount (const char *target, unsigned long flags, const char *data, libcrun_error_t *err)
{
  int ret;

  ret = mount (NULL, target, NULL, flags, data);
  if (UNLIKELY (ret < 0))
    {
      unsigned long remount_flags;
      struct statfs sfs;

      ret = statfs (target, &sfs);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "statfs '%s'", target);

      remount_flags = sfs.f_flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC);

      ret = mount (NULL, target, NULL, flags | remount_flags, data);
      if (LIKELY (ret == 0))
        return 0;

      /* If it still fails try to add MS_RDONLY.  */
      if (sfs.f_flags & MS_RDONLY)
        {
          remount_flags = sfs.f_flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY);
          ret = mount ("none", target, "", flags | remount_flags, data);
        }
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "remount '%s'", target);
    }
  return 0;
}

static int
finalize_mounts (libcrun_container_t *container, libcrun_error_t *err)
{
  int ret = 0;
  struct remount_s *r = get_private_data (container)->remounts;
  while (r)
    {
      struct remount_s *next = r->next;

      ret = do_remount (r->target, r->flags, r->data, err);
      if (UNLIKELY (ret < 0))
        goto cleanup;

      free_remount (r);
      r = next;
    }

 cleanup:
  while (r)
    {
      struct remount_s *next = r->next;
      free_remount (r);
      r = next;
    }

  get_private_data (container)->remounts = NULL;
  return ret;
}

static int
do_mount (libcrun_container_t *container,
          const char *source,
          const char *target,
          const char *fstype,
          unsigned long mountflags,
          const void *data,
          int skip_labelling,
          libcrun_error_t *err)
{
  int ret = 0;
  cleanup_free char *data_with_label = NULL;
  const char *label = container->container_def->linux->mount_label;
  bool needs_remount = false;

  if (!skip_labelling)
    {
      ret = add_selinux_mount_label (&data_with_label, data, label, err);
      if  (ret < 0)
        return ret;
      data = data_with_label;
    }

#define ALL_PROPAGATIONS (MS_REC | MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)
#define ALL_PROPAGATIONS_NO_REC (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)

  if ((fstype && fstype[0]) || (mountflags & MS_BIND))
    {
      unsigned long flags = mountflags & ~(ALL_PROPAGATIONS_NO_REC | MS_RDONLY);

      ret = mount (source, target, fstype, flags, data);
      if (UNLIKELY (ret < 0))
        {
          int saved_errno = errno;

          if (strcmp (fstype ? fstype : "", "sysfs") == 0)
            {
              /* If we are running in an user namespace, just bind mount /sys if creating
                 sysfs failed.  */
              ret = check_running_in_user_namespace (err);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = mount ("/sys", target, "/sys", MS_BIND | MS_REC | MS_SLAVE, data);
              if (LIKELY (ret == 0))
                return 0;
            }

          return crun_make_error (err, saved_errno, "mount '%s' to '%s'", source, target);
        }

      if ((flags & MS_BIND) && (flags & ~(MS_BIND | MS_RDONLY | ALL_PROPAGATIONS)))
        needs_remount = true;
    }

  if (mountflags & ALL_PROPAGATIONS)
    {
      unsigned long rec = mountflags & MS_REC;
      unsigned long propagations = mountflags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE);
      unsigned long all_propagations[] = {MS_SHARED, MS_PRIVATE, MS_SLAVE, MS_UNBINDABLE, 0};
      size_t s;
      for (s = 0; all_propagations[s]; s++)
        {
          if (!(propagations & all_propagations[s]))
            continue;
          ret = mount (NULL, target, NULL, rec | all_propagations[s], NULL);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "set propagation for '%s'", target);
        }
    }

  if (mountflags & MS_RDONLY)
    needs_remount = true;

  if (needs_remount)
    {
      unsigned long remount_flags = MS_REMOUNT | MS_BIND | (mountflags & ~ALL_PROPAGATIONS);

      if ((remount_flags & MS_RDONLY) == 0)
        {
          ret = do_remount (target, remount_flags, NULL, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          struct remount_s *r;

          r = make_remount (target, remount_flags, NULL, get_private_data (container)->remounts);
          get_private_data (container)->remounts = r;
        }
    }

  return ret;
}

static int
do_mount_cgroup_v2 (libcrun_container_t *container,
                    const char *target,
                    unsigned long mountflags,
                    libcrun_error_t *err)
{
  int ret;
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (cgroup_mode < 0)
    return cgroup_mode;

  ret = do_mount (container, "cgroup2", target, "cgroup2", mountflags, NULL, 1, err);
  if (UNLIKELY (ret < 0))
    {
      if (crun_error_get_errno (err) == EPERM || crun_error_get_errno (err) == EBUSY)
        {
          crun_error_release (err);

          ret = do_mount (container, "/sys/fs/cgroup", target, NULL, MS_BIND | mountflags, NULL, 0, err);
        }
      return ret;
    }

  return 0;
}

static bool
has_mount_for (libcrun_container_t *container, const char *destination)
{
  size_t i;
  oci_container *def = container->container_def;

  for (i = 0; i < def->mounts_len; i++)
    {
          if (strcmp (def->mounts[i]->destination, destination) == 0)
            return true;
    }
  return false;
}

static int
do_mount_cgroup_v1 (libcrun_container_t *container,
                    const char *source,
                    const char *target,
                    unsigned long mountflags,
                    libcrun_error_t *err)
{
  int ret;
  const cgroups_subsystem_t *subsystems = NULL;
  cleanup_free char *content = NULL;
  char *from;
  char *saveptr = NULL;

  subsystems = libcrun_get_cgroups_subsystems (err);
  if (UNLIKELY (subsystems == NULL))
    return -1;

  ret = do_mount (container, source, target, "tmpfs", mountflags, "size=1024k", 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_all_file ("/proc/self/cgroup", &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, errno, "invalid content from /proc/self/cgroup");

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *source_path = NULL;
      cleanup_free char *source_subsystem = NULL;
      cleanup_free char *subsystem_path = NULL;
      char *subpath, *subsystem, *it;
      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      if (subsystem[0] == '\0')
        continue;

      it = strstr (subsystem, "name=");
      if (it)
        subsystem += 5;

      xasprintf (&source_subsystem, "/sys/fs/cgroup/%s", subsystem);

      /* if there is already a mount specified, do not add a default one.  */
      if (has_mount_for (container, source_subsystem))
        continue;

      xasprintf (&source_path, "%s/%s", source_subsystem, subpath);
      xasprintf (&subsystem_path, "%s/%s", target, subsystem);

      ret = mkdir (subsystem_path, 0755);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "mkdir for '%s' failed", subsystem_path);

      ret = do_mount (container, source_path, subsystem_path, NULL, MS_BIND | mountflags, NULL, 0, err);
      if (UNLIKELY (ret < 0))
        {
          if (crun_error_get_errno (err) == ENOENT || crun_error_get_errno (err) == ENODEV)
            {
              /* We are trying to mount a subsystem that is not present.  */
              crun_error_release (err);
              continue;
            }
          return ret;
        }
    }

  ret = libcrun_cgroups_create_symlinks (target, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
do_mount_cgroup (libcrun_container_t *container,
                 const char *source,
                 const char *target,
                 unsigned long mountflags,
                 libcrun_error_t *err)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (cgroup_mode < 0)
    return cgroup_mode;

  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      return do_mount_cgroup_v2 (container, target, mountflags, err);
    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      return do_mount_cgroup_v1 (container, source, target, mountflags, err);
    }

  return crun_make_error (err, 0, "unknown cgroups mode %d", cgroup_mode);
}

struct device_s
{
  const char *path;
  char *type;
  int major;
  int minor;
  int mode;
};

struct device_s needed_devs[] =
  {
    {"/dev/null", "c", 1, 3, 0666},
    {"/dev/zero", "c", 1, 5, 0666},
    {"/dev/full", "c", 1, 7, 0666},
    {"/dev/tty", "c", 5, 0, 0666},
    {"/dev/random", "c", 1, 8, 0666},
    {"/dev/urandom", "c", 1, 9, 0666},
    {NULL, '\0', 0, 0, 0}
  };

static int
create_dev (libcrun_container_t *container, int devfd, struct device_s *device, const char *rootfs, bool binds, bool ensure_parent_dir, libcrun_error_t *err)
{
  int ret;
  dev_t dev;
  mode_t type = (device->type[0] == 'b') ? S_IFBLK : ((device->type[0] == 'p') ? S_IFIFO : S_IFCHR);
  const char *fullname = device->path;
  if (binds)
    {
      char *path_to_container, buffer[PATH_MAX];

      path_to_container = chroot_realpath (rootfs, device->path, buffer);
      if (path_to_container == NULL)
        return crun_make_error (err, errno, "cannot resolve '%s'", device->path);

      ret = crun_ensure_file (path_to_container, 0700, true, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_mount (container, fullname, path_to_container, NULL, MS_BIND | MS_PRIVATE, NULL, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      dev = makedev (device->major, device->minor);

      if (device->path[0] != '/')
        {
          ret = mknodat (devfd, device->path, device->mode | type, dev);
          /* We don't fail when the file already exists.  */
          if (UNLIKELY (ret < 0 && errno == EEXIST))
            return 0;
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "mknod '%s'", device->path);

          ret = fchmodat (devfd, device->path, device->mode, 0);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "fchmodat '%s'", device->path);
        }
      else
        {
          char *resolved_path, buffer[PATH_MAX];

          resolved_path = chroot_realpath (rootfs, device->path, buffer);
          if (resolved_path == NULL)
            return crun_make_error (err, errno, "cannot resolve '%s'", device->path);

          if (ensure_parent_dir)
            {
              char *tmp;

              tmp = strrchr (resolved_path, '/');
              if (tmp != resolved_path)
                {
                  *tmp = '\0';
                  ret = crun_ensure_directory (resolved_path, 0700, true, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  *tmp = '/';
                }
            }

          ret = mknod (resolved_path, device->mode | type, dev);
          /* We don't fail when the file already exists.  */
          if (UNLIKELY (ret < 0 && errno == EEXIST))
            return 0;
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "mknod '%s'", device->path);

          ret = chmod (resolved_path, device->mode);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "fchmodat '%s'", device->path);
        }

    }
  return 0;
}

struct symlink_s
{
  const char *path;
  const char *target;
};

static struct symlink_s symlinks[] =
  {
    {"/proc/self/fd", "fd"},
    {"/proc/self/fd/0", "stdin"},
    {"/proc/self/fd/1", "stdout"},
    {"/proc/self/fd/2", "stderr"},
    {"/proc/kcore", "core"},
    {"pts/ptmx", "ptmx"},
    {NULL, NULL}
  };

static int
create_missing_devs (libcrun_container_t *container, const char *rootfs, bool binds, libcrun_error_t *err)
{
  int ret;
  size_t i;
  struct device_s *it;
  cleanup_close int dirfd = open (rootfs, O_DIRECTORY | O_RDONLY);
  cleanup_close int devfd = -1;
  oci_container *def = container->container_def;

  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open rootfs directory '%s'", rootfs);

  devfd = openat (dirfd, "dev", O_RDONLY | O_DIRECTORY);
  if (UNLIKELY (devfd < 0))
    return crun_make_error (err, errno, "open /dev directory in '%s'", rootfs);

  for (i = 0; i < def->linux->devices_len; i++)
    {
      struct device_s device = {def->linux->devices[i]->path,
                                     def->linux->devices[i]->type,
                                     def->linux->devices[i]->major,
                                     def->linux->devices[i]->minor,
                                     def->linux->devices[i]->file_mode};
      ret = create_dev (container, devfd, &device, rootfs, binds, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (it = needed_devs; it->path; it++)
    {
      /* make sure the parent directory exists only on the first iteration.  */
      ret = create_dev (container, devfd, it, rootfs, binds, it == needed_devs, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (i = 0; symlinks[i].target; i++)
    {
      ret = symlinkat (symlinks[i].path, devfd, symlinks[i].target);
      if (UNLIKELY (ret < 0 && errno != EEXIST))
        return crun_make_error (err, errno, "creating symlink for /dev/%s", symlinks[i].target);
    }

  return 0;
}

static int
do_masked_and_readonly_paths (libcrun_container_t *container, const char *rootfs, libcrun_error_t *err)
{
  size_t i;
  int ret;
  oci_container *def = container->container_def;

  for (i = 0; i < def->linux->masked_paths_len; i++)
    {
      cleanup_free char *path = NULL;
      int dir;
      xasprintf (&path, "%s/%s", rootfs, def->linux->masked_paths[i]);

      ret = crun_path_exists (path, err);
      if (UNLIKELY (ret < 0))
        {
          if (errno != EACCES)
            return ret;

          crun_error_release (err);
          continue;
        }

      if (ret == 0)
        continue;

      dir = crun_dir_p (path, true, err);
      if (UNLIKELY (dir < 0))
        return ret;

      if (dir)
        ret = do_mount (container, "tmpfs", path, "tmpfs", MS_RDONLY, "size=0k", 0, err);
      else
        ret = do_mount (container, "/dev/null", path, NULL, MS_BIND | MS_UNBINDABLE | MS_REC, NULL, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  for (i = 0; i < def->linux->readonly_paths_len; i++)
    {
      cleanup_free char *path = NULL;

      xasprintf (&path, "%s/%s", rootfs, def->linux->readonly_paths[i]);

      ret = crun_path_exists (path, err);
      if (UNLIKELY (ret < 0))
        {
          if (errno != EACCES)
            return ret;

          crun_error_release (err);
          continue;
        }

      if (ret == 0)
        continue;

      ret = do_mount (container, path, path, NULL, MS_BIND | MS_PRIVATE | MS_RDONLY | MS_REC, NULL, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
do_pivot (libcrun_container_t *container, const char *rootfs, libcrun_error_t *err)
{
  int ret;
  cleanup_close int oldrootfd = open ("/", O_DIRECTORY | O_RDONLY);
  cleanup_close int newrootfd = open (rootfs, O_DIRECTORY | O_RDONLY);

  if (UNLIKELY (oldrootfd < 0))
    return crun_make_error (err, errno, "open '/'");
  if (UNLIKELY (newrootfd < 0))
    return crun_make_error (err, errno, "open '%s'", rootfs);

  ret = fchdir (newrootfd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fchdir '%s'", rootfs);

  ret = pivot_root (".", ".");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pivot_root");

  ret = fchdir (oldrootfd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fchdir '%s'", rootfs);

  ret = do_mount (container, NULL, ".", NULL, MS_REC | MS_PRIVATE, NULL, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = umount2 (".", MNT_DETACH);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "umount oldroot");

  do
    {
      ret = umount2 (".", MNT_DETACH);
      if (ret < 0 && errno == EINVAL)
        break;
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "umount oldroot");
    }
  while (ret == 0);

  ret = chdir ("/");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to newroot");

  return 0;
}

static int
get_default_flags (libcrun_container_t *container, const char *destination, char **data)
{
  if (strcmp (destination, "/proc") == 0)
      return 0;
  if (strcmp (destination, "/dev/cgroup") == 0
      || strcmp (destination, "/sys/fs/cgroup") == 0)
    {
      *data = xstrdup ("none,name=");
      return MS_NOEXEC | MS_NOSUID | MS_STRICTATIME;
    }
  if (strcmp (destination, "/dev") == 0)
    {
      *data = xstrdup ("mode=755");
      return MS_NOEXEC | MS_STRICTATIME;
    }
  if (strcmp (destination, "/dev/shm") == 0)
    {
      *data = xstrdup ("mode=1777,size=65536k");
      return MS_NOEXEC | MS_NOSUID | MS_NODEV;
    }
  if (strcmp (destination, "/dev/mqueue") == 0)
      return MS_NOEXEC | MS_NOSUID | MS_NODEV;
  if (strcmp (destination, "/dev/pts") == 0)
    {
      if (container->host_uid == 0)
        *data = xstrdup ("newinstance,ptmxmode=0666,mode=620,gid=5");
      else
        *data = xstrdup ("newinstance,ptmxmode=0666,mode=620");
      return MS_NOEXEC | MS_NOSUID;
    }
  if (strcmp (destination, "/sys") == 0)
      return MS_NOEXEC | MS_NOSUID | MS_NODEV;

  return 0;
}

static int
do_mounts (libcrun_container_t *container, const char *rootfs, libcrun_error_t *err)
{
  size_t i;
  int ret;
  oci_container *def = container->container_def;
  for (i = 0; i < def->mounts_len; i++)
    {
      cleanup_free char *target_buffer = NULL;
      cleanup_free char *data = NULL;
      char *type;
      char *source;
      unsigned long flags = 0;
      unsigned long extra_flags = 0;
      int skip_labelling;
      int is_dir = 1;
      char *resolved_path, buffer_resolved_path[PATH_MAX];
      char *target = NULL;
      cleanup_close int copy_from_fd = -1;

      resolved_path = chroot_realpath (rootfs, def->mounts[i]->destination, buffer_resolved_path);
      if (resolved_path != NULL)
        target = resolved_path;
      else
        {
          if (errno != ENOENT)
            return crun_make_error (err, errno, "cannot resolve %s", def->mounts[i]->destination);

          resolved_path = def->mounts[i]->destination;
          if (!rootfs)
            target = def->mounts[i]->destination;
          else
            {
              xasprintf (&target_buffer, "%s/%s", rootfs, resolved_path + 1);
              target = target_buffer;
            }
        }

      type = def->mounts[i]->type;

      if (def->mounts[i]->options == NULL)
        flags = get_default_flags (container, def->mounts[i]->destination, &data);
      else
        {
          size_t j;

          for (j = 0; j < def->mounts[i]->options_len; j++)
            flags |= get_mount_flags_or_option (def->mounts[i]->options[j], flags, &extra_flags, &data);

          if (type == NULL)
            {
              size_t j;

              for (j = 0; j < def->mounts[i]->options_len; j++)
                {
                  if (strcmp (def->mounts[i]->options[j], "bind") == 0 || strcmp (def->mounts[i]->options[j], "rbind") == 0)
                    {
                      type = "bind";
                      break;
                    }
                }
            }
        }

      if (type == NULL)
        return crun_make_error (err, 0, "invalid mount type for %s", def->mounts[i]->destination);

      if (strcmp (type, "bind") == 0)
        {
          if (strcmp (def->mounts[i]->destination, "/dev") == 0)
            get_private_data (container)->mount_dev_from_host = true;
          flags |= MS_BIND;
        }

      if (def->mounts[i]->source && (flags & MS_BIND))
        {
          is_dir = crun_dir_p (def->mounts[i]->source, false, err);
          if (UNLIKELY (is_dir < 0))
            return is_dir;

          if (data == NULL || strstr (data, "mode=") == NULL)
            {
              bool append;

              append = data != NULL && data[0] != '\0';

              if (data != NULL)
                {
                  free (data);
                  data = NULL;
                }

              if (append)
                xasprintf (&data, "%s,%s", data, "mode=1755");
              else
                data = xstrdup ("mode=1755");
            }
        }

      if (is_dir)
        {
          ret = crun_ensure_directory (target, 01755, true, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = crun_ensure_file (target, 0755, true, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (extra_flags & OPTION_TMPCOPYUP)
        {
          if (strcmp (type, "tmpfs") != 0)
            return crun_make_error (err, errno, "tmpcopyup can be used only with tmpfs");

          copy_from_fd = open (target, O_DIRECTORY);
          if (UNLIKELY (copy_from_fd < 0))
            {
              if (errno != ENOTDIR)
                return crun_make_error (err, errno, "open target for tmpcopyup");
            }
        }

      source = def->mounts[i]->source ? def->mounts[i]->source : type;

      skip_labelling = strcmp (type, "sysfs") == 0
        || strcmp (type, "proc") == 0
        || strcmp (type, "mqueue") == 0;

      if (strcmp (type, "cgroup") == 0)
        {
          ret = do_mount_cgroup (container, source, target, flags, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = do_mount (container, source, target, type, flags, data, skip_labelling, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (copy_from_fd >= 0)
        {
          int destfd, tmpfd;

          destfd = open (target, O_DIRECTORY);
          if (UNLIKELY (destfd < 0))
            return crun_make_error (err, errno, "open target to write for tmpcopyup");

          /* take ownership for the fd.  */
          tmpfd = copy_from_fd;
          copy_from_fd = -1;

          ret = copy_recursive_fd_to_fd (tmpfd, destfd, target, target, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

    }
  return 0;
}

/*
  Open a fd to the NOTIFY_SOCKET end on the host.  If CONTAINER is NULL, then CONTEXT
  is used to retrieve the path to the socket.
*/
int
get_notify_fd (libcrun_context_t *context, libcrun_container_t *container, int *notify_socket_out, libcrun_error_t *err)
{
#ifdef HAVE_SYSTEMD
  cleanup_close int notify_fd = -1;
  cleanup_free char *host_notify_socket_path = NULL;
  cleanup_free char *state_dir = NULL;
  char *host_path = NULL;

  if (container)
    host_path = get_private_data (container)->host_notify_socket_path;

  *notify_socket_out = -1;

  if (host_path == NULL)
    {
      state_dir = libcrun_get_state_directory (context->state_root, context->id);
      xasprintf (&host_notify_socket_path, "%s/notify/notify", state_dir);
      host_path = host_notify_socket_path;
    }

  notify_fd = open_unix_domain_socket (host_path, 1, err);
  if (UNLIKELY (notify_fd < 0))
    return notify_fd;

  if (UNLIKELY (chmod (host_path, 0777) < 0))
    return crun_make_error (err, errno, "chmod %s", host_path);

  *notify_socket_out = notify_fd;
  notify_fd = -1;
  return 1;
#else
  (void) context;
  (void) container;
  (void) err;
  *notify_socket_out = -1;
  return 0;
#endif
}

#ifdef HAVE_SYSTEMD
static int
do_notify_socket (libcrun_container_t *container, const char *rootfs, libcrun_error_t *err)
{
  int ret;
  const char *notify_socket = container->context->notify_socket;
  cleanup_free char *host_notify_socket_path = NULL;
  cleanup_free char *host_notify_socket_path_dir = NULL;
  cleanup_free char *container_notify_socket_path = NULL;
  cleanup_free char *state_dir = libcrun_get_state_directory (container->context->state_root, container->context->id);

  if (notify_socket == NULL)
    return 0;

  xasprintf (&container_notify_socket_path, "%s%s", rootfs, notify_socket);
  xasprintf (&host_notify_socket_path_dir, "%s/notify", state_dir);
  xasprintf (&host_notify_socket_path, "%s/notify", state_dir);

  ret = mkdir (host_notify_socket_path_dir, 0700);
  if (ret < 0)
    return crun_make_error (err, errno, "mkdir %s", host_notify_socket_path_dir);

  get_private_data (container)->host_notify_socket_path = host_notify_socket_path;
  get_private_data (container)->container_notify_socket_path = container_notify_socket_path;
  host_notify_socket_path = container_notify_socket_path = NULL;
  return 0;
}
#endif

static int
do_finalize_notify_socket (libcrun_container_t *container, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *host_notify_socket_path = get_private_data (container)->host_notify_socket_path;
  cleanup_free char *container_notify_socket_path = get_private_data (container)->container_notify_socket_path;
  cleanup_free char *container_notify_socket_path_dir_alloc = NULL;
  char *container_notify_socket_path_dir = NULL;

  get_private_data (container)->host_notify_socket_path = get_private_data (container)->container_notify_socket_path = NULL;

  if (host_notify_socket_path == NULL || container_notify_socket_path == NULL)
    return 0;

  container_notify_socket_path_dir_alloc = xstrdup (container_notify_socket_path);
  container_notify_socket_path_dir = dirname (container_notify_socket_path_dir_alloc);

  ret = crun_ensure_directory (container_notify_socket_path_dir, 0755, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_mount (container, host_notify_socket_path, container_notify_socket_path_dir, NULL,
                  MS_BIND | MS_REC | MS_PRIVATE, NULL, 0, err);
  if (UNLIKELY (ret < 0))
   return ret;

  return 0;
}

static int
make_parent_mount_private (const char *rootfs, libcrun_error_t *err)
{
  cleanup_free char *tmp = xstrdup (rootfs);
  char *it;

  for (;;)
    {
      int ret;

      ret = mount (NULL, tmp, NULL, MS_PRIVATE, NULL);
      if (ret == 0)
        return 0;

      if (errno == EINVAL)
        {
          it = strrchr (tmp, '/');
          if (it == NULL)
            return 0;
          else if (it != tmp)
            {
              *it = '\0';
              continue;
            }
          else
            {
              ret = mount (NULL, "/", NULL, MS_PRIVATE, NULL);
              if (ret == 0)
                return 0;
            }
        }
      return crun_make_error (err, errno, "make %s private", tmp);
    }
  return 0;
}

int
libcrun_set_mounts (libcrun_container_t *container, const char *rootfs, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret = 0, is_user_ns = 0;
  unsigned long rootfs_propagation = 0;

  if (def->linux->rootfs_propagation)
    rootfs_propagation = get_mount_flags (def->linux->rootfs_propagation, 0, NULL, NULL);

  if ((rootfs_propagation & (MS_SHARED | MS_SLAVE | MS_PRIVATE | MS_UNBINDABLE)) == 0)
    rootfs_propagation = MS_REC | MS_PRIVATE;

  get_private_data (container)->rootfs_propagation = rootfs_propagation;

  if (get_private_data (container)->unshare_flags & CLONE_NEWNS)
    {
      ret = do_mount (container, NULL, "/", NULL, rootfs_propagation, NULL, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = make_parent_mount_private (rootfs, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_mount (container, rootfs, rootfs, NULL, MS_BIND | MS_REC | MS_PRIVATE, NULL, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->root->readonly)
    {
      unsigned long remount_flags = MS_REMOUNT | MS_BIND | MS_RDONLY;
      struct remount_s *r = make_remount (rootfs, remount_flags, NULL, get_private_data (container)->remounts);
      get_private_data (container)->remounts = r;
    }

  ret = libcrun_container_enter_cgroup_ns (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_mounts (container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  is_user_ns = (get_private_data (container)->unshare_flags & CLONE_NEWUSER);
  if (!is_user_ns)
    {
      is_user_ns = check_running_in_user_namespace (err);
      if (UNLIKELY (is_user_ns < 0))
        return is_user_ns;
    }

  if (!get_private_data (container)->mount_dev_from_host)
    {
      ret = create_missing_devs (container, rootfs, is_user_ns ? true : false, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = do_finalize_notify_socket (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_masked_and_readonly_paths (container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = finalize_mounts (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
move_root (const char *rootfs, libcrun_error_t *err)
{
  int ret;

  ret = chdir (rootfs);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to '%s'", rootfs);

  ret = umount2 ("/sys", MNT_DETACH);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "umount /sys");

  ret = umount2 ("/proc", MNT_DETACH);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "umount /proc");

  ret = mount (rootfs, "/", "", MS_MOVE, "");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mount MS_MOVE to '/'");

  ret = chroot (".");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chroot to '%s'", rootfs);

  ret = chdir ("/");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to '%s'", rootfs);

  return 0;
}

int
libcrun_do_pivot_root (libcrun_container_t *container, bool no_pivot, const char *rootfs, libcrun_error_t *err)
{
  int ret;
  if (get_private_data (container)->unshare_flags & CLONE_NEWNS)
    {
      if (no_pivot)
        {
          ret = move_root (rootfs, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = do_pivot (container, rootfs, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = do_mount (container, NULL, "/", NULL, get_private_data (container)->rootfs_propagation, NULL, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = chroot (rootfs);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "chroot to '%s'", rootfs);
    }

  ret = chdir ("/");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to /");

  return 0;
}

static int
uidgidmap_helper (char *helper, pid_t pid, char *map_file, libcrun_error_t *err)
{
#define MAX_ARGS 20
  char pid_fmt[16];
  char *args[MAX_ARGS + 1];
  char *next;
  size_t nargs = 0;
  args[nargs++] = helper;
  sprintf (pid_fmt, "%d", pid);
  args[nargs++] = pid_fmt;
  next = map_file;
  while (nargs < MAX_ARGS)
    {
      char *p = strsep (&next, " \n");
      if (next == NULL)
        break;
      args[nargs++] = p;
    }
  args[nargs++] = NULL;

  return run_process (args, err) ? -1 : 0;
}

static int
newgidmap (pid_t pid, char *map_file, libcrun_error_t *err)
{
  return uidgidmap_helper ("/usr/bin/newgidmap", pid, map_file, err);
}

static int
newuidmap (pid_t pid, char *map_file, libcrun_error_t *err)
{
  return uidgidmap_helper ("/usr/bin/newuidmap", pid, map_file, err);
}

static int
deny_setgroups (libcrun_container_t *container, pid_t pid, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *groups_file = NULL;

  xasprintf (&groups_file, "/proc/%d/setgroups", pid);
  ret = write_file (groups_file, "deny", 4, err);
  if (ret >= 0)
    get_private_data (container)->deny_setgroups = true;
  return ret;
}

static int
can_setgroups (libcrun_container_t *container, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *content = NULL;

  if (get_private_data (container)->deny_setgroups)
    return 0;

  if (container->container_def->annotations)
    {
      const char *annotation;

      /* Skip setgroups if the annotation is set to anything different than "0".  */
      annotation = find_annotation (container, "run.oci.keep_original_groups");
      if (annotation)
        return strcmp (annotation, "0") == 0 ? 1 : 0;
    }

  ret = read_all_file ("/proc/self/setgroups", &content, NULL, err);
  if (ret < 0)
    return ret;

  return strncmp (content, "deny", 4) == 0 ? 0 : 1;
}

int
libcrun_container_enter_cgroup_ns (libcrun_container_t *container, libcrun_error_t *err)
{
#ifdef CLONE_NEWCGROUP
  if (get_private_data (container)->unshare_flags & CLONE_NEWCGROUP)
    {
      int ret = unshare (CLONE_NEWCGROUP);
      if (UNLIKELY (ret < 0))
        {
          if (errno != EINVAL)
            return crun_make_error (err, errno, "unshare (CLONE_NEWCGROUP)");
        }
    }
#endif
  return 0;
}

int
libcrun_set_usernamespace (libcrun_container_t *container, pid_t pid, libcrun_error_t *err)
{
#define MAPPING_FMT_SIZE ("%" PRIu32 " %" PRIu32 " %" PRIu32 "\n")
#define MAPPING_FMT_1 ("%" PRIu32 " %" PRIu32 " 1\n")
  cleanup_free char *uid_map_file = NULL;
  cleanup_free char *gid_map_file = NULL;
  cleanup_free char *uid_map = NULL;
  cleanup_free char *gid_map = NULL;
  int uid_map_len, gid_map_len;
  int ret;
  oci_container *def = container->container_def;

  if ((get_private_data (container)->unshare_flags & CLONE_NEWUSER) == 0)
    return 0;

  if (!def->linux->uid_mappings_len)
    {
      uid_map_len = format_default_id_mapping (&uid_map, container->container_uid, container->host_uid, 1);
      if (uid_map == NULL)
        {
          if (container->host_uid)
            uid_map_len = xasprintf (&uid_map, MAPPING_FMT_1, 0, container->host_uid);
          else
            uid_map_len = xasprintf (&uid_map, MAPPING_FMT_SIZE, 0, container->host_uid, container->container_uid + 1);
        }
    }
  else
    {
      size_t written = 0, s;
      char buffer[64];
      uid_map = xmalloc (sizeof (buffer) * def->linux->uid_mappings_len + 1);
      for (s = 0; s < def->linux->uid_mappings_len; s++)
        {
          size_t len;

          len = sprintf (buffer, MAPPING_FMT_SIZE,
                         def->linux->uid_mappings[s]->container_id,
                         def->linux->uid_mappings[s]->host_id,
                         def->linux->uid_mappings[s]->size);
          memcpy (uid_map + written, buffer, len);
          written += len;
        }
      uid_map[written] = '\0';
      uid_map_len = written;
    }

  if (!def->linux->gid_mappings_len)
    {
      gid_map_len = format_default_id_mapping (&gid_map, container->container_gid, container->host_uid, 0);
      if (gid_map == NULL)
        {
          if (container->host_gid)
            gid_map_len = xasprintf (&gid_map, MAPPING_FMT_1, container->container_gid, container->host_gid);
          else
            gid_map_len = xasprintf (&gid_map, MAPPING_FMT_SIZE, 0, container->host_gid, container->container_gid + 1);
        }
    }
  else
    {
      size_t written = 0, s;
      char buffer[64];
      gid_map = xmalloc (sizeof (buffer) * def->linux->gid_mappings_len + 1);
      for (s = 0; s < def->linux->gid_mappings_len; s++)
        {
          size_t len;

          len = sprintf (buffer, MAPPING_FMT_SIZE,
                         def->linux->gid_mappings[s]->container_id,
                         def->linux->gid_mappings[s]->host_id,
                         def->linux->gid_mappings[s]->size);
          memcpy (gid_map + written, buffer, len);
          written += len;
        }
      gid_map[written] = '\0';
      gid_map_len = written;
    }

  if (container->host_uid)
    ret = newgidmap (pid, gid_map, err);
  if (container->host_uid == 0 || ret < 0)
    {
      crun_error_release (err);

      xasprintf (&gid_map_file, "/proc/%d/gid_map", pid);
      ret = write_file (gid_map_file, gid_map, gid_map_len, err);
      if (ret < 0 && !def->linux->gid_mappings_len)
        {
          size_t single_mapping_len;
          char single_mapping[32];
          crun_error_release (err);

          ret = deny_setgroups (container, pid, err);
          if (UNLIKELY (ret < 0))
            return ret;

          single_mapping_len = sprintf (single_mapping, MAPPING_FMT_1, container->container_gid, container->host_gid);
          ret = write_file (gid_map_file, single_mapping, single_mapping_len, err);
        }
    }
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->host_uid)
    ret = newuidmap (pid, uid_map, err);
  if (container->host_uid == 0 || ret < 0)
    {
      crun_error_release (err);

      xasprintf (&uid_map_file, "/proc/%d/uid_map", pid);
      ret = write_file (uid_map_file, uid_map, uid_map_len, err);
      if (ret < 0 && !def->linux->uid_mappings_len)
        {
          size_t single_mapping_len;
          char single_mapping[32];
          crun_error_release (err);

          if (!get_private_data (container)->deny_setgroups)
            {
              ret = deny_setgroups (container, pid, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }

          single_mapping_len = sprintf (single_mapping, MAPPING_FMT_1, container->container_uid, container->host_uid);
          ret = write_file (uid_map_file, single_mapping, single_mapping_len, err);
        }
    }
  if (UNLIKELY (ret < 0))
    return ret;
  return 0;

#undef MAPPING_FMT_SIZE
#undef MAPPING_FMT_1
}

#define CAP_TO_MASK_0(x) (1L << ((x) & 31))
#define CAP_TO_MASK_1(x) CAP_TO_MASK_0(x - 32)

struct all_caps_s
{
  unsigned long effective[2];
  unsigned long permitted[2];
  unsigned long inheritable[2];
  unsigned long ambient[2];
  unsigned long bounding[2];
};

static int
has_cap_on (int cap, long unsigned *caps)
{
  if (cap < 32)
    return CAP_TO_MASK_0 (cap) & caps[0];
  return (CAP_TO_MASK_1 (cap) & caps[1]);
}

static int
set_required_caps (struct all_caps_s *caps, uid_t uid, gid_t gid, int no_new_privs, libcrun_error_t *err)
{
  unsigned long cap;
  int ret;
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[2] = { { 0 } };

  for (cap = 0; cap <= CAP_LAST_CAP; cap++)
    if (! has_cap_on (cap, caps->bounding))
      {
        ret = prctl (PR_CAPBSET_DROP, cap, 0, 0, 0);
        if (UNLIKELY (ret < 0 && !(errno == EINVAL)))
          return crun_make_error (err, errno, "prctl drop bounding");
      }

  data[0].effective = caps->effective[0];
  data[1].effective = caps->effective[1];
  data[0].inheritable = caps->inheritable[0];
  data[1].inheritable = caps->inheritable[1];
  data[0].permitted = caps->permitted[0];
  data[1].permitted = caps->permitted[1];

  ret = prctl (PR_SET_KEEPCAPS, 1, 0, 0, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error while setting PR_SET_KEEPCAPS");

  ret = setgid (gid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot setgid");

  ret = setuid (uid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot setuid");

  ret = capset (&hdr, data);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "capset");

#ifdef PR_CAP_AMBIENT
  ret = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
  if (UNLIKELY (ret < 0 && !(errno == EINVAL || errno == EPERM)))
    return crun_make_error (err, errno, "prctl reset ambient");

  for (cap = 0; cap <= CAP_LAST_CAP; cap++)
    if (has_cap_on (cap, caps->ambient))
      {
        ret = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
        if (UNLIKELY (ret < 0 && !(errno == EINVAL || errno == EPERM)))
          return crun_make_error (err, errno, "prctl ambient raise");
      }
#endif

  if (no_new_privs)
    if (UNLIKELY (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0))
      return crun_make_error (err, errno, "no new privs");

  return 0;
}

static int
read_caps (unsigned long caps[2], char **values, size_t len, libcrun_error_t *err)
{
  size_t i;
  for (i = 0; i < len; i++)
    {
      cap_value_t cap;
      if (cap_from_name (values[i], &cap) < 0)
        return crun_make_error (err, 0, "unknown cap: %s", values[i]);
      if (cap < 32)
          caps[0] |= CAP_TO_MASK_0 (cap);
      else
          caps[1] |= CAP_TO_MASK_1 (cap);
    }
  return 0;
}

int
libcrun_set_selinux_exec_label (oci_container_process *proc, libcrun_error_t *err)
{
  if (proc->selinux_label)
    return set_selinux_exec_label (proc->selinux_label, err);

  return 0;
}

int
libcrun_set_apparmor_profile (oci_container_process *proc, libcrun_error_t *err)
{
  if (proc->apparmor_profile)
    return set_apparmor_profile (proc->apparmor_profile, err);
  return 0;
}

int
libcrun_set_caps (oci_container_process_capabilities *capabilities, uid_t uid, gid_t gid, int no_new_privileges, libcrun_error_t *err)
{
  int ret;
  struct all_caps_s caps;

  memset (&caps, 0, sizeof (caps));
  if (capabilities)
    {
      ret = read_caps (caps.effective,
                       capabilities->effective,
                       capabilities->effective_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.inheritable,
                       capabilities->inheritable,
                       capabilities->inheritable_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.ambient,
                       capabilities->ambient,
                       capabilities->ambient_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.bounding,
                       capabilities->bounding,
                       capabilities->bounding_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.permitted,
                       capabilities->permitted,
                       capabilities->permitted_len,
                       err);
      if (ret < 0)
        return ret;
    }

  return set_required_caps (&caps, uid, gid, no_new_privileges, err);
}

struct rlimit_s
{
  const char *name;
  int value;
};

struct rlimit_s rlimits[] =
  {
    {"RLIMIT_AS", RLIMIT_AS},
    {"RLIMIT_CORE", RLIMIT_CORE},
    {"RLIMIT_CPU", RLIMIT_CPU},
    {"RLIMIT_DATA", RLIMIT_DATA},
    {"RLIMIT_FSIZE", RLIMIT_FSIZE},
    {"RLIMIT_LOCKS", RLIMIT_LOCKS},
    {"RLIMIT_MEMLOCK", RLIMIT_MEMLOCK},
    {"RLIMIT_MSGQUEUE", RLIMIT_MSGQUEUE},
    {"RLIMIT_NICE", RLIMIT_NICE},
    {"RLIMIT_NOFILE", RLIMIT_NOFILE},
    {"RLIMIT_NPROC", RLIMIT_NPROC},
    {"RLIMIT_RSS", RLIMIT_RSS},
    {"RLIMIT_RTPRIO", RLIMIT_RTPRIO},
    {"RLIMIT_RTTIME", RLIMIT_RTTIME},
    {"RLIMIT_SIGPENDING", RLIMIT_SIGPENDING},
    {"RLIMIT_STACK", RLIMIT_STACK},
    {NULL, 0}
  };

static int
get_rlimit_resource (const char *name)
{
  struct rlimit_s *it;
  for (it = rlimits; it->name; it++)
    if (strcmp (it->name, name) == 0)
      return it->value;
  return -1;
}

int
libcrun_set_rlimits (oci_container_process_rlimits_element **new_rlimits, size_t len, libcrun_error_t *err)
{
  size_t i;
  for (i = 0; i < len; i++)
    {
      struct rlimit limit;
      char *type = new_rlimits[i]->type;
      int resource = get_rlimit_resource (type);
      if (UNLIKELY (resource < 0))
        return crun_make_error (err, errno, "invalid rlimit '%s'", type);
      limit.rlim_cur = new_rlimits[i]->soft;
      limit.rlim_max = new_rlimits[i]->hard;
      if (UNLIKELY (setrlimit (resource, &limit) < 0))
        return crun_make_error (err, errno, "setrlimit '%s'", type);
    }
  return 0;
}

int
libcrun_set_hostname (libcrun_container_t *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int has_uts = get_private_data (container)->unshare_flags & CLONE_NEWUTS;
  int ret;
  if (def->hostname == NULL || def->hostname[0] == '\0')
    return 0;
  if (!has_uts)
    return crun_make_error (err, 0, "hostname requires the UTS namespace");
  ret = sethostname (def->hostname, strlen (def->hostname));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sethostname");
  return 0;
}

int
libcrun_set_oom (libcrun_container_t *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  cleanup_close int fd = -1;
  int ret;
  char oom_buffer[16];
  if (def->process == NULL || def->process->oom_score_adj == 0)
    return 0;
  sprintf (oom_buffer, "%i", def->process->oom_score_adj);
  fd = open ("/proc/self/oom_score_adj", O_RDWR);
  if (fd < 0)
    return crun_make_error (err, errno, "open /proc/self/oom_score_adj");
  ret = TEMP_FAILURE_RETRY (write (fd, oom_buffer, strlen (oom_buffer)));
  if (ret < 0)
    return crun_make_error (err, errno, "write to /proc/self/oom_score_adj");
  return 0;
}

int
libcrun_set_sysctl (libcrun_container_t *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  size_t i;
  cleanup_close int dirfd = -1;

  if (!def->linux || !def->linux->sysctl)
    return 0;

  dirfd = open ("/proc/sys", O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open /proc/sys");

  for (i = 0; i < def->linux->sysctl->len; i++)
    {
      cleanup_free char *name = xstrdup (def->linux->sysctl->keys[i]);
      cleanup_close int fd = -1;
      int ret;
      char *it;
      for (it = name; *it; it++)
        if (*it == '.')
          *it = '/';

      fd = openat (dirfd, name, O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open /proc/sys/%s", name);

      ret = TEMP_FAILURE_RETRY (write (fd, def->linux->sysctl->values[i], strlen (def->linux->sysctl->values[i])));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write to /proc/sys/%s", name);
    }
  return 0;
}

static int
open_terminal (libcrun_container_t *container, char **slave, libcrun_error_t *err)
{
  int ret;
  cleanup_close int fd = -1;

  fd = libcrun_new_terminal (slave, err);
  if (UNLIKELY (fd < 0))
    return fd;

  ret = libcrun_set_stdio (*slave, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->container_def->process
      && container->container_def->process->user
      && container->container_def->process->user->uid)
    {
      ret = chown (*slave, container->container_def->process->user->uid, -1);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "chown %s", *slave);
    }

  ret = fd;
  fd = -1;
  return ret;
}

int
libcrun_set_terminal (libcrun_container_t *container, libcrun_error_t *err)
{
  int ret;
  cleanup_close int fd = -1;
  cleanup_free char *slave = NULL;
  oci_container *def = container->container_def;

  if (def->process == NULL || !def->process->terminal)
    return 0;

  fd = open_terminal (container, &slave, err);
  if (UNLIKELY (fd < 0))
    return fd;

  if (def->process->console_size)
    {
      ret = libcrun_terminal_setup_size (0, def->process->console_size->height,
                                         def->process->console_size->width,
                                         err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = write_file ("/dev/console", NULL, 0, err);
  if (UNLIKELY (ret < 0))
    {
      int ret_exists;
      libcrun_error_t tmp_err = NULL;

      ret_exists = crun_path_exists ("/dev/console", &tmp_err);
      /* Always ignore errors from crun_path_exists.  */
      if (UNLIKELY (ret_exists < 0))
        crun_error_release (&tmp_err);

      /* If the file doesn't exist or crun_path_exists failed, return the original error.  */
      if (ret_exists <= 0)
        return ret;

      /* Otherwise ignore errors and try to bind mount on top of it.  */
      crun_error_release (err);
    }

  ret = do_mount (container, slave, "/dev/console", NULL, MS_BIND, NULL, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = fd;
  fd = -1;

  return ret;
}

pid_t
libcrun_run_linux_container (libcrun_container_t *container,
                             int detach,
                             container_entrypoint_t entrypoint,
                             void *args,
                             int *sync_socket_out,
                             libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  size_t i;
  int ret;
  int flags_unshare = 0, flags = 0;
  pid_t pid, pid_container = 0;
  cleanup_close int sync_socket_host = -1;
  cleanup_close int sync_socket_container = -1;
  int sync_socket[2];
#define MAX_NAMESPACES 10
  cleanup_close_vec int *namespaces_to_join = (int[MAX_NAMESPACES+1]){-1};
  int namespaces_to_join_index[MAX_NAMESPACES];
  size_t n_namespaces_to_join = 0;
  int userns_join_index = -1;

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: %s", def->linux->namespaces[i]->type);

      if (def->linux->namespaces[i]->path == NULL)
        {
          if (value != CLONE_NEWUSER)
            flags_unshare |= value;
        }
      else
        {
          int fd;

          if (n_namespaces_to_join >= MAX_NAMESPACES)
            return crun_make_error (err, 0, "too many namespaces to join");

          fd = open (def->linux->namespaces[i]->path, O_RDONLY);
          if (UNLIKELY (fd < 0))
              return crun_make_error (err, errno, "open '%s'", def->linux->namespaces[i]->path);

          if (value == CLONE_NEWUSER)
            userns_join_index = n_namespaces_to_join;

          namespaces_to_join[n_namespaces_to_join] = fd;
          namespaces_to_join_index[n_namespaces_to_join] = i;
          n_namespaces_to_join++;
          namespaces_to_join[n_namespaces_to_join] = -1;
        }

      flags |= value;
    }

  if (container->host_uid && (flags & CLONE_NEWUSER) == 0)
    {
      libcrun_warning ("non root user need to have an 'user' namespace");
      flags |= CLONE_NEWUSER;
    }

  get_private_data (container)->unshare_flags = flags;
#ifdef CLONE_NEWCGROUP
  /* cgroup will be unshared later.  */
  flags &= ~CLONE_NEWCGROUP;
#endif

  ret = socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sync_socket);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "socketpair");

  sync_socket_host = sync_socket[0];
  sync_socket_container = sync_socket[1];

#ifdef HAVE_SYSTEMD
  ret = do_notify_socket (container, def->root->path, err);
  if (UNLIKELY (ret < 0))
    return ret;
#endif

  get_uid_gid_from_def (container->container_def,
                        &container->container_uid,
                        &container->container_gid);

  /* This must be done before we enter a user namespace.  */
  if (def->process)
    {
      ret = libcrun_set_rlimits (def->process->rlimits, def->process->rlimits_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_set_oom (container, err);
  if (UNLIKELY (ret < 0))
      goto out;

  /* If we create a new user namespace, create it as part of the clone.  */
  pid = syscall_clone ((flags & ((userns_join_index >= 0) ? 0 : CLONE_NEWUSER)) | (detach ? 0 : SIGCHLD), NULL);
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "clone");

  if (pid)
    {
      pid_t grandchild = 0;

      ret = close_and_reset (&sync_socket_container);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "close");
      sync_socket_container = -1;

      if ((flags & CLONE_NEWUSER) && (userns_join_index < 0))
        {
          ret = libcrun_set_usernamespace (container, pid, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (write (sync_socket_host, "1", 1));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write to sync socket");
        }

      if (flags & CLONE_NEWPID)
        {
          ret = TEMP_FAILURE_RETRY (read (sync_socket_host, &grandchild, sizeof (grandchild)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read pid from sync socket");
        }

      *sync_socket_out = sync_socket_host;
      sync_socket_host = -1;

      return grandchild ? grandchild : pid;
    }

  /* In the container.  Join namespaces if asked and jump into the entrypoint function.  */
  ret = close_and_reset (&sync_socket_host);
  if (UNLIKELY (ret < 0))
    {
      crun_make_error (err, errno, "close");
      goto out;
    }
  sync_socket_host = -1;

  ret = libcrun_set_oom (container, err);
  if (UNLIKELY (ret < 0))
      goto out;

  if (flags & CLONE_NEWUSER)
    {
      if (userns_join_index < 0)
        {
          char tmp;

          ret = TEMP_FAILURE_RETRY (read (sync_socket_container, &tmp, 1));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read from sync socket");
        }
      else
        {
          /* If we need to join another user namespace, do it immediately before creating any other namespace. */
          ret = setns (namespaces_to_join[userns_join_index], CLONE_NEWUSER);
          if (UNLIKELY (ret < 0))
            {
              crun_make_error (err, errno, "cannot setns '%s'", def->linux->namespaces[userns_join_index]->path);
              goto out;
            }
        }

      ret = setgid (0);
      if (UNLIKELY (ret < 0))
        {
          crun_make_error (err, errno, "setgid(0)");
          goto out;
        }

      ret = setuid (0);
      if (UNLIKELY (ret < 0))
        {
          crun_make_error (err, errno, "setgid(0)");
          goto out;
        }
    }

  for (i = 0; i < n_namespaces_to_join; i++)
    {
      cleanup_free char *cwd = NULL;
      int orig_index = namespaces_to_join_index[i];
      int value = find_namespace (def->linux->namespaces[orig_index]->type);

      /* The user namespace is handled differently and already joined at this point.  */
      if (value == CLONE_NEWUSER)
        continue;

      if (value == CLONE_NEWNS)
        {
          cwd = get_current_dir_name ();
          if (UNLIKELY (cwd == NULL))
            {
              crun_make_error (err, errno, "cannot get current working directory");
              goto out;
            }
        }

      ret = setns (namespaces_to_join[i], value);
      if (UNLIKELY (ret < 0))
        {
          crun_make_error (err, errno, "cannot setns '%s'", def->linux->namespaces[orig_index]->path);
          goto out;
        }
      if (value == CLONE_NEWNS)
        {
          ret = chdir (cwd);
          if (UNLIKELY (ret < 0))
            {
              crun_make_error (err, errno, "chdir(.)");
              goto out;
            }
        }
    }

  if (flags_unshare)
    {
      /* New namespaces to create for the container.  */
      ret = unshare (flags_unshare);
      if (UNLIKELY (ret < 0))
        goto out;
    }

  if (flags & CLONE_NEWPID)
    {
      /* A PID namespace is joined when a new process is created.  */
      pid_container = fork ();
      if (UNLIKELY (ret < 0))
        {
          crun_make_error (err, errno, "cannot fork");
          goto out;
        }

      /* Report back the new PID.  */
      if (pid_container)
        {
          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &pid_container, sizeof (pid_container)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write to sync socket");
          _exit (EXIT_SUCCESS);
        }
    }

  if (def->process && def->process->user)
    {
      gid_t *additional_gids = NULL;
      size_t additional_gids_len = 0;
      int can_do_setgroups;

      additional_gids = def->process->user->additional_gids;
      additional_gids_len = def->process->user->additional_gids_len;

      can_do_setgroups = can_setgroups (container, err);
      if (UNLIKELY (can_do_setgroups < 0))
        goto out;

      if (can_do_setgroups)
        {
          ret = setgroups (additional_gids_len, additional_gids);
          if (UNLIKELY (ret < 0))
            {
              crun_make_error (err, errno, "setgroups");
              goto out;
            }
        }
    }

  entrypoint (args, container->context->notify_socket, sync_socket_container, err);

  /* ENTRYPOINT returns only on an error, fallback here: */

 out:
  if (*err)
    libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
  _exit (EXIT_FAILURE);
}

static int
join_process_parent_helper (pid_t child_pid,
                            int sync_socket_fd,
                            libcrun_container_status_t *status,
                            int *terminal_fd,
                            libcrun_error_t *err)
{
  int ret, pid_status;
  char res;
  pid_t pid;
  cleanup_close int sync_fd = sync_socket_fd;

  if (terminal_fd)
    *terminal_fd = -1;

  /* Read the status and the PID from the child process.  */
  ret = TEMP_FAILURE_RETRY (read (sync_fd, &res, 1));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from sync socket");

  if (res != '0')
    return crun_make_error (err, 0, "fail startup");

  ret = TEMP_FAILURE_RETRY (read (sync_fd, &pid, sizeof (pid)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from sync socket");

  /* Wait for the child pid so we ensure the grandchild gets properly reparented.  */
  ret = TEMP_FAILURE_RETRY (waitpid (child_pid, &pid_status, 0));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "waitpid for exec child pid");

  ret = libcrun_move_process_to_cgroup (pid, status->cgroup_path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* The write unblocks the grandchild process so it can run once we setup
     the cgroups.  */
  ret = TEMP_FAILURE_RETRY (write (sync_fd, &ret, sizeof (ret)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to sync socket");

  if (terminal_fd)
    {
      ret = receive_fd_from_socket (sync_fd, err);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "receive fd");
      *terminal_fd = ret;
    }

  return pid;
}

static int
inherit_env (pid_t pid_to_join, libcrun_error_t *err)
{
  int ret = 0;
  size_t len;
  char *str;
  cleanup_free char *path;
  /* Not a memory leak here.  The data used by putenv must not be freed.  */
  char *content = NULL;

  xasprintf (&path, "/proc/%d/environ", pid_to_join);

  ret = read_all_file (path, &content, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (str = content; str < content + len; str += strlen (str) + 1)
    if (putenv (str) < 0)
        return crun_make_error (err, errno, "putenv '%s'", str);
  return ret;
}

int
libcrun_join_process (libcrun_container_t *container, pid_t pid_to_join, libcrun_container_status_t *status, int detach, int *terminal_fd, libcrun_error_t *err)
{
  pid_t pid;
  int ret;
  int sync_socket_fd[2];
  int fds[10] = {-1, };
  int fds_joined[10] = {0, };
  const char *all_namespaces[] = {"ipc", "mnt",  "net", "pid", "uts",
#ifdef CLONE_NEWCGROUP
                                  "cgroup",
#endif
                                  "user",
                                  NULL};
  oci_container *def = container->container_def;
  size_t i;
  cleanup_close int sync_fd = -1;

  if (! detach)
    {
      ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "set child subreaper");
    }

  ret = socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sync_socket_fd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error creating socketpair");

  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      crun_make_error (err, errno, "fork");
      goto exit;
    }
  if (pid)
    {
      close_and_reset (&sync_socket_fd[1]);
      sync_fd = sync_socket_fd[0];
      return join_process_parent_helper (pid, sync_fd, status, terminal_fd, err);
    }

  close_and_reset (&sync_socket_fd[0]);
  sync_fd = sync_socket_fd[1];

  ret = clearenv ();
  if (UNLIKELY (ret < 0))
    {
      crun_make_error (err, 0, "clearenv");
      goto exit;
    }

  ret = inherit_env (pid_to_join, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  if (def->linux->namespaces_len >= 10)
    {
      crun_make_error (err, 0, "invalid configuration");
      goto exit;
    }

  for (i = 0; all_namespaces[i]; i++)
    {
      cleanup_close int fd = -1;
      cleanup_free char *ns_join;
      xasprintf (&ns_join, "/proc/%d/ns/%s", pid_to_join, all_namespaces[i]);
      fds[i] = open (ns_join, O_RDONLY);
      if (UNLIKELY (fds[i] < 0))
        {
          ret = crun_make_error (err, errno, "open '%s'", ns_join);
          goto exit;
        }
    }
  for (i = 0; all_namespaces[i]; i++)
    {
      ret = setns (fds[i], 0);
      if (ret == 0)
        fds_joined[i] = 1;
    }
  for (i = 0; all_namespaces[i]; i++)
    {
      if (fds_joined[i])
        continue;
      ret = setns (fds[i], 0);
      if (UNLIKELY (ret < 0 && errno != EINVAL))
        {
          size_t j;
          bool found = false;

          for (j = 0; j < def->linux->namespaces_len; j++)
            {
              if (strcmp (all_namespaces[i], def->linux->namespaces[j]->type) == 0)
                {
                  found = true;
                  break;
                }
            }
          if (!found)
            {
              /* It was not requested to create this ns, so just ignore it.  */
              fds_joined[i] = 1;
              continue;
            }
          crun_make_error (err, errno, "setns '%s'", all_namespaces[i]);
          goto exit;
        }
      fds_joined[i] = 1;
    }
  for (i = 0; all_namespaces[i]; i++)
    close_and_reset (&fds[i]);

  if (detach && setsid () < 0)
    {
      crun_make_error (err, errno, "setsid");
      goto exit;
    }

  /* We need to fork once again to join the PID namespace.  */
  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      ret = TEMP_FAILURE_RETRY (write (sync_fd, "1", 1));
      crun_make_error (err, errno, "fork");
      goto exit;
    }

  if (pid)
    {
      /* Just return the PID to the parent helper and exit.  */
      ret = TEMP_FAILURE_RETRY (write (sync_fd, "0", 1));
      if (UNLIKELY (ret < 0))
        _exit (EXIT_FAILURE);

      ret = TEMP_FAILURE_RETRY (write (sync_fd, &pid, sizeof (pid)));
      if (UNLIKELY (ret < 0))
        _exit (EXIT_FAILURE);

      _exit (EXIT_SUCCESS);
    }
  else
    {
      /* Inside the grandchild process.  The real process
         used for the container.  */
      int r = -1;
      cleanup_free char *slave = NULL;

      ret = TEMP_FAILURE_RETRY (read (sync_fd, &r, sizeof (r)));
      if (UNLIKELY (ret < 0))
        _exit (EXIT_FAILURE);

      if (terminal_fd)
        {
          cleanup_close int master_fd = -1;

          if (setsid () < 0)
            libcrun_fail_with_error (errno, "setsid");

          master_fd = open_terminal (container, &slave, err);
          if (UNLIKELY (master_fd < 0))
            {
              crun_error_write_warning_and_release (stderr, &err);
              _exit (EXIT_FAILURE);
            }

          ret = send_fd_to_socket (sync_fd, master_fd, err);
          if (UNLIKELY (ret < 0))
            {
              crun_error_write_warning_and_release (stderr, &err);
              _exit (EXIT_FAILURE);
            }
        }

      if (r != 0)
        _exit (EXIT_FAILURE);
    }

  return pid;

 exit:
  if (sync_socket_fd[0] >= 0)
    TEMP_FAILURE_RETRY (close (sync_socket_fd[0]));
  if (sync_socket_fd[1] >= 0)
    TEMP_FAILURE_RETRY (close (sync_socket_fd[1]));
  for (i = 0; all_namespaces[i]; i++)
    if (fds[i] >= 0)
      TEMP_FAILURE_RETRY (close (fds[i]));
  return ret;
}

int
libcrun_linux_container_update (libcrun_container_status_t *status, const char *content, size_t len arg_unused, libcrun_error_t *err)
{
  int ret;
  yajl_val tree = NULL;
  parser_error parser_err = NULL;
  oci_container_linux_resources *resources = NULL;
  struct parser_context ctx = {0, stderr};
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (cgroup_mode < 0)
    return cgroup_mode;

  ret = parse_json_file (&tree, content, &ctx, err);
  if (UNLIKELY (ret < 0))
    return -1;

  resources = make_oci_container_linux_resources (tree, &ctx, &parser_err);
  if (UNLIKELY (resources == NULL))
    {
      ret = crun_make_error (err, errno, "cannot parse resources");
      goto cleanup;
    }

  ret = libcrun_update_cgroup_resources (cgroup_mode, resources, status->cgroup_path, err);

 cleanup:
  if (tree)
    yajl_tree_free (tree);
  free (parser_err);
  if (resources)
    free_oci_container_linux_resources (resources);

  return ret;
}

static int
libcrun_container_pause_unpause_linux (libcrun_container_status_t *status, const bool pause, libcrun_error_t *err)
{
  return libcrun_cgroup_pause_unpause (status->cgroup_path, pause, err);
}

int
libcrun_container_pause_linux (libcrun_container_status_t *status, libcrun_error_t *err)
{
  return libcrun_container_pause_unpause_linux (status, true, err);
}

int
libcrun_container_unpause_linux (libcrun_container_status_t *status, libcrun_error_t *err)
{
  return libcrun_container_pause_unpause_linux (status, false, err);
}

int
libcrun_set_personality (oci_container_linux_personality *p, libcrun_error_t *err)
{
  unsigned long persona = 0;
  int ret;

  if (strcmp (p->domain, "LINUX") == 0)
      persona = PER_LINUX;
  else if (strcmp (p->domain, "LINUX32") == 0)
      persona = PER_LINUX32;
  else
    return crun_make_error (err, 0, "unknown persona specified '%s'", p->domain);

  ret = personality (persona);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "set personality to '%s'", p->domain);

  return 0;
}

/* Protection for attacks like CVE-2019-5736.  */
int ensure_cloned_binary ();
__attribute__((constructor)) static void libcrun_rexec(void)
{
  if (ensure_cloned_binary () < 0)
    {
      fprintf (stderr, "Failed to re-execute libcrun via memory file descriptor\n");
      _exit (EXIT_FAILURE);
    }
}
