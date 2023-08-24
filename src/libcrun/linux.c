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
#include "linux.h"
#include "utils.h"
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#ifdef HAVE_FSCONFIG_CMD_CREATE_LINUX_MOUNT_H
#  include <linux/mount.h>
#endif
#if defined HAVE_FSCONFIG_CMD_CREATE_LINUX_MOUNT_H || defined HAVE_FSCONFIG_CMD_CREATE_SYS_MOUNT_H
#  define HAVE_NEW_MOUNT_API
#endif

#include <sys/prctl.h>
#ifdef HAVE_CAP
#  include <sys/capability.h>
#endif
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <signal.h>
#include "terminal.h"
#include "cgroup.h"
#include "cgroup-utils.h"
#include "status.h"
#include "criu.h"
#include "scheduler.h"
#include "io_priority.h"

#include <sys/socket.h>
#include <libgen.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/personality.h>
#include <net/if.h>
#include <sys/xattr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sched.h>

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

#include "mount_flags.h"

#define YAJL_STR(x) ((const unsigned char *) (x))

#ifndef RLIMIT_RTTIME
#  define RLIMIT_RTTIME 15
#endif

#ifndef OPEN_TREE_CLONE
#  define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#  define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#  define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

#ifndef MOVE_MOUNT_T_EMPTY_PATH
#  define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#endif

struct remount_s
{
  struct remount_s *next;
  char *target;
  int targetfd;
  unsigned long flags;
  char *data;
};

struct private_data_s
{
  struct remount_s *remounts;

  /* Filled by libcrun_run_linux_container().  Useful to query what
     namespaces are available.  */
  int unshare_flags;

#if CLONE_NEWCGROUP
  int unshare_cgroupns;
#endif

  char *host_notify_socket_path;
  char *container_notify_socket_path;
  bool mount_dev_from_host;
  unsigned long rootfs_propagation;
  bool deny_setgroups;

  const char *rootfs;
  int rootfsfd;

  size_t rootfs_len;
  int notify_socket_tree_fd;

  struct libcrun_fd_map *mount_fds;
  struct libcrun_fd_map *dev_fds;

  /* Used to save stdin, stdout, stderr during checkpointing to descriptors.json
   * and needed during restore. */
  char *external_descriptors;
};

struct linux_namespace_s
{
  const char *name;
  const char *ns_file;
  int value;
};

static void
cleanup_private_data (void *private_data)
{
  struct private_data_s *p = private_data;

  if (p->rootfsfd >= 0)
    TEMP_FAILURE_RETRY (close (p->rootfsfd));
  if (p->mount_fds)
    cleanup_close_mapp (&(p->mount_fds));
  if (p->dev_fds)
    cleanup_close_mapp (&(p->dev_fds));

  free (p->host_notify_socket_path);
  free (p->container_notify_socket_path);
  free (p->external_descriptors);
  free (p);
}

static struct private_data_s *
get_private_data (struct libcrun_container_s *container)
{
  if (container->private_data == NULL)
    {
      struct private_data_s *p = xmalloc0 (sizeof (*p));
      container->private_data = p;
      p->rootfsfd = -1;
      p->notify_socket_tree_fd = -1;
      container->cleanup_private_data = cleanup_private_data;
    }
  return container->private_data;
}

#ifndef CLONE_NEWTIME
#  define CLONE_NEWTIME 0
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP 0
#endif
#ifndef AT_RECURSIVE
#  define AT_RECURSIVE 0x8000
#endif

static struct linux_namespace_s namespaces[] = { { "mount", "mnt", CLONE_NEWNS },
                                                 { "network", "net", CLONE_NEWNET },
                                                 { "ipc", "ipc", CLONE_NEWIPC },
                                                 { "pid", "pid", CLONE_NEWPID },
                                                 { "uts", "uts", CLONE_NEWUTS },
                                                 { "user", "user", CLONE_NEWUSER },
#if CLONE_NEWCGROUP
                                                 { "cgroup", "cgroup", CLONE_NEWCGROUP },
#endif
#if CLONE_NEWTIME
                                                 { "time", "time", CLONE_NEWTIME },
#endif
                                                 { NULL, NULL, 0 } };

static int
get_and_reset (int *old)
{
  int tmp = *old;
  *old = -1;
  return tmp;
}

int
libcrun_find_namespace (const char *name)
{
  struct linux_namespace_s *it;
  for (it = namespaces; it->name; it++)
    if (strcmp (it->name, name) == 0)
      return it->value;
  return -1;
}

#ifndef __aligned_u64
#  define __aligned_u64 uint64_t __attribute__ ((aligned (8)))
#endif

#ifndef CLONE_INTO_CGROUP
#  define CLONE_INTO_CGROUP 0x200000000ULL
#endif

struct _clone3_args
{
  __aligned_u64 flags;
  __aligned_u64 pidfd;
  __aligned_u64 child_tid;
  __aligned_u64 parent_tid;
  __aligned_u64 exit_signal;
  __aligned_u64 stack;
  __aligned_u64 stack_size;
  __aligned_u64 tls;
  __aligned_u64 set_tid;
  __aligned_u64 set_tid_size;
  __aligned_u64 cgroup;
};

static int
syscall_clone3 (struct _clone3_args *args)
{
#ifdef __NR_clone3
  return (int) syscall (__NR_clone3, args, sizeof (*args));
#else
  (void) args;
  errno = ENOSYS;
  return -1;
#endif
}

static int
syscall_fsopen (const char *fs_name, unsigned int flags)
{
#if defined __NR_fsopen
  return (int) syscall (__NR_fsopen, fs_name, flags);
#else
  (void) fs_name;
  (void) flags;
  errno = ENOSYS;
  return -1;
#endif
}

static int
syscall_fsmount (int fsfd, unsigned int flags, unsigned int attr_flags)
{
#if defined __NR_fsmount
  return (int) syscall (__NR_fsmount, fsfd, flags, attr_flags);
#else
  (void) fsfd;
  (void) flags;
  (void) attr_flags;
  errno = ENOSYS;
  return -1;
#endif
}

static int
syscall_fsconfig (int fsfd, unsigned int cmd, const char *key, const void *val, int aux)
{
#if defined __NR_fsconfig
  return (int) syscall (__NR_fsconfig, fsfd, cmd, key, val, aux);
#else
  (void) fsfd;
  (void) cmd;
  (void) key;
  (void) val;
  (void) aux;
  errno = ENOSYS;
  return -1;
#endif
}

static int
syscall_move_mount (int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned int flags)

{
#if defined __NR_move_mount
  return (int) syscall (__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
#else
  (void) from_dfd;
  (void) from_pathname;
  (void) to_dfd;
  (void) to_pathname;
  (void) flags;
  errno = ENOSYS;
  return -1;
#endif
}

/* ignore this being unused - it's (currently) only unused if not building with systemd,
   but conditioning the definition of syscall_open_tree on HAVE_SYSTEMD seems pretty silly */
__attribute__ ((unused)) static int
syscall_open_tree (int dfd, const char *pathname, unsigned int flags)

{
#if defined __NR_open_tree
  return (int) syscall (__NR_open_tree, dfd, pathname, flags);
#else
  (void) dfd;
  (void) pathname;
  (void) flags;
  errno = ENOSYS;
  return -1;
#endif
}

struct mount_attr_s
{
  uint64_t attr_set;
  uint64_t attr_clr;
  uint64_t propagation;
  uint64_t userns_fd;
};

#ifndef MOUNT_ATTR_RDONLY
#  define MOUNT_ATTR_RDONLY 0x00000001 /* Mount read-only */
#endif

#ifndef MOUNT_ATTR_IDMAP
#  define MOUNT_ATTR_IDMAP 0x00100000 /* Idmap mount to @userns_fd in struct mount_attr. */
#endif

static int
syscall_mount_setattr (int dfd, const char *path, unsigned int flags,
                       struct mount_attr_s *attr)
{
#ifdef __NR_mount_setattr
  return (int) syscall (__NR_mount_setattr, dfd, path, flags, attr, sizeof (*attr));
#else
  (void) dfd;
  (void) path;
  (void) flags;
  (void) attr;
  errno = ENOSYS;
  return -1;
#endif
}

static int
syscall_keyctl_join (const char *name)
{
#define KEYCTL_JOIN_SESSION_KEYRING 0x1
  return (int) syscall (__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, name, 0);
}

static int
syscall_pidfd_open (pid_t pid, unsigned int flags)
{
#if defined __NR_pidfd_open
  return (int) syscall (__NR_pidfd_open, pid, flags);
#else
  (void) pid;
  (void) flags;
  errno = ENOSYS;
  return -1;
#endif
}

static int
syscall_pidfd_send_signal (int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
#if defined __NR_pidfd_send_signal
  return (int) syscall (__NR_pidfd_send_signal, pidfd, sig, info, flags);
#else
  (void) pidfd;
  (void) sig;
  (void) info;
  (void) flags;
  errno = ENOSYS;
  return -1;
#endif
}

static int
do_mount_setattr (const char *target, int targetfd, uint64_t clear, uint64_t set, libcrun_error_t *err)
{
  struct mount_attr_s attr = {
    0,
  };
  int ret;

  attr.attr_set = set;
  attr.attr_clr = clear;

  ret = syscall_mount_setattr (targetfd, "", AT_RECURSIVE | AT_EMPTY_PATH, &attr);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mount_setattr `/%s`", target);

  return 0;
}

static int
get_bind_mount (int dirfd, const char *src, bool recursive, bool rdonly, libcrun_error_t *err)
{
  cleanup_close int open_tree_fd = -1;
  struct mount_attr_s attr = {
    0,
  };
  int recursive_flag = (recursive ? AT_RECURSIVE : 0);
  int ret;

  if (rdonly)
    attr.attr_set = MS_RDONLY;

  errno = 0;
  open_tree_fd = syscall_open_tree (dirfd, src,
                                    AT_NO_AUTOMOUNT | OPEN_TREE_CLOEXEC
                                        | OPEN_TREE_CLONE | recursive_flag);
  if (UNLIKELY (open_tree_fd < 0))
    return crun_make_error (err, errno, "open_tree `%s`", src);

  ret = syscall_mount_setattr (open_tree_fd, "", AT_EMPTY_PATH | recursive_flag, &attr);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mount_setattr `%s`", src);

  return get_and_reset (&open_tree_fd);
}

int
parse_idmapped_mount_option (runtime_spec_schema_config_schema *def, bool is_uids, char *option, char **out, size_t *len, libcrun_error_t *err)
{
  size_t written = 0, allocated = 256;
  cleanup_free char *mappings = NULL;
  const char *it;

  mappings = xmalloc (allocated);

  for (it = option; *it;)
    {
      bool relative = false;
      long value[3];
      size_t i;

      if (*it == '\0')
        break;

      if (*it == '#')
        it++;

      if (*it == '@')
        {
          relative = true;
          it++;
        }

      /* read a triplet: file system id - host id - size.  */
      for (i = 0; i < 3; i++)
        {
          char *endptr = NULL;

          if (i > 0 && *it == '-')
            it++;

          if (*it == '\0')
            return crun_make_error (err, errno, "invalid mapping specified `%s`", option);

          errno = 0;
          value[i] = strtol (it, &endptr, 10);
          if (errno || endptr == it)
            return crun_make_error (err, errno, "invalid mapping specified `%s`", option);

          it = endptr;
        }

      if (relative)
        {
          runtime_spec_schema_defs_id_mapping **mappings;
          size_t mappings_len;

          if (def == NULL
              || def->linux == NULL
              || (is_uids && def->linux->uid_mappings_len == 0)
              || (! is_uids && def->linux->gid_mappings_len == 0))
            return crun_make_error (err, 0, "specified a relative mapping without user namespace mappings");

          mappings_len = (is_uids ? def->linux->uid_mappings_len : def->linux->gid_mappings_len);
          mappings = is_uids ? def->linux->uid_mappings : def->linux->gid_mappings;

          for (i = 0; i < mappings_len; i++)
            if (value[0] >= mappings[i]->container_id && value[0] < mappings[i]->container_id + mappings[i]->size)
              break;

          if (i == mappings_len)
            return crun_make_error (err, 0, "could not find a user namespace mapping for the relative mapping `%s`", option);

          value[1] += mappings[i]->host_id - mappings[i]->container_id;
        }
      if (written > allocated - 64)
        {
          allocated += 256;
          mappings = xrealloc (mappings, allocated);
        }
      written += sprintf (mappings + written, "%ld %ld %ld\n", value[0], value[1], value[2]);
    }
  *(mappings + written) = '\0';

  *len = written;

  *out = mappings;
  mappings = NULL;

  return 0;
}

static char *
format_mount_mappings (runtime_spec_schema_defs_id_mapping **mappings, size_t mappings_len, size_t *written)
{
  /* 64 is more than enough room to print 3 uint32.  */
  const size_t max_len_mapping = 64;
  char *ret;
  size_t s;

  *written = 0;

  ret = xmalloc (max_len_mapping * mappings_len + 1);
  for (s = 0; s < mappings_len; s++)
    {
      size_t len;

      len = snprintf (ret + *written, max_len_mapping, "%" PRIu32 " %" PRIu32 " %" PRIu32 "\n",
                      mappings[s]->container_id,
                      mappings[s]->host_id,
                      mappings[s]->size);

      *written += len;
    }
  return ret;
}

static char *
format_mount_mapping (uint32_t container_id, uint32_t host_id, uint32_t size, size_t *written)
{
  runtime_spec_schema_defs_id_mapping mapping = {
    .container_id = container_id,
    .host_id = host_id,
    .size = size,
  };
  runtime_spec_schema_defs_id_mapping *mappings[] = {
    &mapping,
    NULL,
  };

  return format_mount_mappings (mappings, 1, written);
}

static bool
has_same_mappings (runtime_spec_schema_config_schema *def, runtime_spec_schema_defs_mount *mnt)
{
  size_t s;

  if (def->linux == NULL)
    return mnt->uid_mappings_len == 0 && mnt->gid_mappings_len == 0;

  if (mnt->uid_mappings_len != def->linux->uid_mappings_len)
    return false;

  if (mnt->gid_mappings_len != def->linux->gid_mappings_len)
    return false;

  for (s = 0; s < mnt->uid_mappings_len; s++)
    {
      if (mnt->uid_mappings[s]->container_id != def->linux->uid_mappings[s]->container_id)
        return false;
      if (mnt->uid_mappings[s]->host_id != def->linux->uid_mappings[s]->host_id)
        return false;
      if (mnt->uid_mappings[s]->size != def->linux->uid_mappings[s]->size)
        return false;
    }

  for (s = 0; s < mnt->gid_mappings_len; s++)
    {
      if (mnt->gid_mappings[s]->container_id != def->linux->gid_mappings[s]->container_id)
        return false;
      if (mnt->gid_mappings[s]->host_id != def->linux->gid_mappings[s]->host_id)
        return false;
      if (mnt->gid_mappings[s]->size != def->linux->gid_mappings[s]->size)
        return false;
    }

  return true;
}

static pid_t
maybe_create_userns_for_idmapped_mount (runtime_spec_schema_config_schema *def,
                                        runtime_spec_schema_defs_mount *mnt,
                                        const char *options, pid_t *pid_out,
                                        libcrun_error_t *err)
{
  cleanup_pid pid_t pid = -1;
  char proc_file[64];
  bool need_new_userns = mnt->uid_mappings_len ? ! has_same_mappings (def, mnt) : options != NULL;

  if (! need_new_userns)
    return 0;

  pid = syscall_clone (CLONE_NEWUSER | SIGCHLD, NULL);
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "clone");

  if (pid == 0)
    {
      prctl (PR_SET_PDEATHSIG, SIGKILL);
      while (1)
        pause ();
      _exit (EXIT_SUCCESS);
    }

  if (mnt->uid_mappings_len)
    {
      cleanup_free char *uid_map = NULL;
      cleanup_free char *gid_map = NULL;
      size_t written = 0;
      int ret;

      uid_map = format_mount_mappings (mnt->uid_mappings, mnt->uid_mappings_len, &written);
      sprintf (proc_file, "/proc/%d/uid_map", pid);
      ret = write_file (proc_file, uid_map, written, err);
      if (UNLIKELY (ret < 0))
        return ret;

      gid_map = format_mount_mappings (mnt->gid_mappings, mnt->gid_mappings_len, &written);
      sprintf (proc_file, "/proc/%d/gid_map", pid);
      ret = write_file (proc_file, gid_map, written, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      cleanup_free char *dup_options = NULL;
      char *option, *saveptr = NULL;

      if (! options)
        return crun_make_error (err, 0, "internal error: no mappings found");

      dup_options = xstrdup (options);

      /* If there are no OCI mappings specified, then parse the annotation.  */
      for (option = strtok_r (dup_options, ";", &saveptr); option; option = strtok_r (NULL, ";", &saveptr))
        {
          cleanup_free char *mappings = NULL;
          bool is_uids = false;
          size_t len = 0;
          int ret;

          if (has_prefix (option, "uids="))
            {
              is_uids = true;
              sprintf (proc_file, "/proc/%d/uid_map", pid);
            }
          else if (has_prefix (option, "gids="))
            sprintf (proc_file, "/proc/%d/gid_map", pid);
          else
            return crun_make_error (err, 0, "invalid option `%s` specified", option);

          ret = parse_idmapped_mount_option (def, is_uids, option + 5 /* strlen ("uids="), strlen ("gids=")*/, &mappings, &len, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = write_file (proc_file, mappings, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  *pid_out = pid;
  pid = -1;
  return 0;
}

int
libcrun_create_keyring (const char *name, const char *label, libcrun_error_t *err)
{
  const char *const keycreate = "/proc/self/attr/keycreate";
  cleanup_close int labelfd = -1;
  bool label_set = false;
  int ret;

  if (label)
    {
      labelfd = open (keycreate, O_WRONLY | O_CLOEXEC);
      if (UNLIKELY (labelfd < 0))
        {
          if (errno != ENOENT)
            return crun_make_error (err, errno, "open `%s`", keycreate);
        }
      else
        {
          ret = write (labelfd, label, strlen (label));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write to `%s`", keycreate);

          label_set = true;
        }
    }

  ret = syscall_keyctl_join (name);
  if (UNLIKELY (ret < 0))
    {
      if (errno == ENOSYS)
        {
          libcrun_warning ("could not create a new keyring: keyctl_join is not supported");
          ret = 0;
          goto out;
        }
      ret = crun_make_error (err, errno, "create keyring `%s`", name);
      goto out;
    }

out:
  /* Best effort attempt to reset the SELinux label used for new keyrings.  */
  if (label_set)
    (void) write (labelfd, "", 0);
  return ret;
}

static void
get_uid_gid_from_def (runtime_spec_schema_config_schema *def, uid_t *uid, gid_t *gid)
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

static unsigned long
get_mount_flags (const char *name, int current_flags, int *found, unsigned long *extra_flags, uint64_t *rec_clear, uint64_t *rec_set)
{
  const struct propagation_flags_s *prop;

  prop = libcrun_str2mount_flags (name);

  if (found)
    *found = prop ? 1 : 0;

  if (prop == NULL)
    return 0;

  if (prop->extra_flags & OPTION_RECURSIVE)
    {
      if (rec_clear && prop->clear)
        *rec_clear |= prop->flags;

      if (rec_set && ! prop->clear)
        *rec_set |= prop->flags;
    }

  if (extra_flags)
    *extra_flags |= prop->extra_flags;

  if (prop->clear)
    return current_flags & ~prop->flags;

  return current_flags | prop->flags;
}

static unsigned long
get_mount_flags_or_option (const char *name, int current_flags, unsigned long *extra_flags, char **option, uint64_t *rec_clear, uint64_t *rec_set)
{
  int found;
  __attribute__ ((unused)) cleanup_free char *prev = NULL;
  unsigned long flags = get_mount_flags (name, current_flags, &found, extra_flags, rec_clear, rec_set);
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
pivot_root (const char *new_root, const char *put_old)
{
  return syscall (__NR_pivot_root, new_root, put_old);
}

static void
free_remount (struct remount_s *r)
{
  if (r->targetfd >= 0)
    close (r->targetfd);
  free (r->data);
  free (r->target);
  free (r);
}

static struct remount_s *
make_remount (int targetfd, const char *target, unsigned long flags, const char *data, struct remount_s *next)
{
  struct remount_s *ret = xmalloc (sizeof (*ret));
  ret->target = xstrdup (target);
  ret->flags = flags;
  ret->data = data ? xstrdup (data) : NULL;
  ret->next = next;
  ret->targetfd = targetfd;
  return ret;
}

static int
do_remount (int targetfd, const char *target, unsigned long flags, const char *data, libcrun_error_t *err)
{
  int ret;
  proc_fd_path_t target_buffer;
  const char *real_target = target;

  if (targetfd >= 0)
    {
      get_proc_self_fd_path (target_buffer, targetfd);
      real_target = target_buffer;
    }

  /* Older kernels (seen on 4.18) fail with EINVAL if data is set when
     setting MS_RDONLY.  */
  if (flags & (MS_REMOUNT | MS_RDONLY))
    data = NULL;

  ret = mount (NULL, real_target, NULL, flags, data);
  if (UNLIKELY (ret < 0))
    {
      unsigned long remount_flags;
      struct statfs sfs;

      ret = statfs (real_target, &sfs);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "statfs `%s`", real_target);

      remount_flags = sfs.f_flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC);

      if ((flags | remount_flags) != flags)
        {
          ret = mount (NULL, real_target, NULL, flags | remount_flags, data);
          if (LIKELY (ret == 0))
            return 0;

          /* If it still fails and MS_RDONLY is present in the mount, try adding it.  */
          if (sfs.f_flags & MS_RDONLY)
            {
              remount_flags = sfs.f_flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY);
              ret = mount (NULL, real_target, NULL, flags | remount_flags, data);
            }
        }
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "remount `%s`", target);
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

      ret = do_remount (r->targetfd, r->target, r->flags, r->data, err);
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
open_mount_target (libcrun_container_t *container, const char *target_rel, libcrun_error_t *err)
{
  const char *rootfs = get_private_data (container)->rootfs;
  size_t rootfs_len = get_private_data (container)->rootfs_len;
  int rootfsfd = get_private_data (container)->rootfsfd;

  if (rootfsfd < 0)
    return crun_make_error (err, 0, "invalid rootfs state");

  return safe_openat (rootfsfd, rootfs, rootfs_len, target_rel, O_PATH | O_CLOEXEC, 0, err);
}

/* Attempt to open a mount of the specified type.  */
static int
fsopen_mount (const char *type, const char *labeltype, const char *label)
{
#ifdef HAVE_NEW_MOUNT_API
  cleanup_close int fsfd = -1;
  int ret;

  fsfd = syscall_fsopen (type, FSOPEN_CLOEXEC);
  if (UNLIKELY (fsfd < 0))
    return fsfd;

  if (labeltype)
    {
      ret = syscall_fsconfig (fsfd, FSCONFIG_SET_STRING, labeltype, label, 0);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = syscall_fsconfig (fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
  if (UNLIKELY (ret < 0))
    return ret;

  return syscall_fsmount (fsfd, FSMOUNT_CLOEXEC, 0);
#else
  (void) type;
  (void) syscall_fsopen;
  (void) syscall_fsconfig;
  (void) syscall_fsmount;
  errno = ENOSYS;
  return -1;
#endif
}

static int
fs_move_mount_to (int fd, int dirfd, const char *name)
{
#ifdef HAVE_NEW_MOUNT_API
  if (name)
    return syscall_move_mount (fd, "", dirfd, name, MOVE_MOUNT_F_EMPTY_PATH);

  return syscall_move_mount (fd, "", dirfd, "", MOVE_MOUNT_T_EMPTY_PATH | MOVE_MOUNT_F_EMPTY_PATH);
#else
  (void) fd;
  (void) dirfd;
  (void) name;
  (void) syscall_move_mount;
  errno = ENOSYS;
  return -1;
#endif
}

enum
{
  /* Do not apply any label to the mount.  */
  LABEL_NONE = 0,
  /* Apply the label as a mount option.  */
  LABEL_MOUNT,
  /* Apply the label using setxattr.  */
  LABEL_XATTR,
};

static int do_mount (libcrun_container_t *container, const char *source, int targetfd,
                     const char *target, const char *fstype, unsigned long mountflags,
                     const void *data, int label_how, libcrun_error_t *err);

static bool
has_mount_for (libcrun_container_t *container, const char *destination)
{
  size_t i;
  runtime_spec_schema_config_schema *def = container->container_def;

  for (i = 0; i < def->mounts_len; i++)
    {
      if (strcmp (def->mounts[i]->destination, destination) == 0)
        return true;
    }
  return false;
}

static int
do_masked_or_readonly_path (libcrun_container_t *container, const char *rel_path, bool readonly, bool keep_flags,
                            libcrun_error_t *err)
{
  unsigned long mount_flags = 0;
  size_t rootfs_len = get_private_data (container)->rootfs_len;
  const char *rootfs = get_private_data (container)->rootfs;
  int rootfsfd = get_private_data (container)->rootfsfd;
  cleanup_close int pathfd = -1;
  struct statfs sfs;
  int ret;
  mode_t mode;

  if (rel_path[0] == '/')
    rel_path++;

  pathfd = safe_openat (rootfsfd, rootfs, rootfs_len, rel_path, O_PATH | O_CLOEXEC, 0, err);
  if (UNLIKELY (pathfd < 0))
    {
      if (errno != ENOENT && errno != EACCES)
        return crun_make_error (err, errno, "open `%s`", rel_path);

      crun_error_release (err);
      return 0;
    }

  if (readonly)
    {
      proc_fd_path_t source_buffer;

      get_proc_self_fd_path (source_buffer, pathfd);
      mount_flags = MS_BIND | MS_PRIVATE | MS_RDONLY | MS_REC;
      if (keep_flags)
        {
          ret = statfs (source_buffer, &sfs);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "statfs `%s`", source_buffer);
          mount_flags = mount_flags | sfs.f_flags;

          // Parent might contain `MS_REMOUNT` but the new readonly path is not
          // actually mounted. Specifically in the case of `/proc` this will end
          // up with EINVAL therefore remove `MS_REMOUNT` if its getting
          // inherited from the parent.
          mount_flags = mount_flags & ~MS_REMOUNT;
        }
      ret = do_mount (container, source_buffer, pathfd, rel_path, NULL, mount_flags, NULL,
                      LABEL_NONE, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = get_file_type_fd (pathfd, &mode);
      if (UNLIKELY (ret < 0))
        return ret;

      if ((mode & S_IFMT) == S_IFDIR)
        ret = do_mount (container, "tmpfs", pathfd, rel_path, "tmpfs", MS_RDONLY, "size=0k", LABEL_MOUNT, err);
      else
        ret = do_mount (container, "/dev/null", pathfd, rel_path, NULL, MS_BIND | MS_RDONLY, NULL, LABEL_MOUNT, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static inline const char *
get_selinux_context_type (libcrun_container_t *container)
{
  const char *context_type;

  context_type = find_annotation (container, "run.oci.mount_context_type");
  if (context_type)
    return context_type;

  return "context";
}

static int
do_mount (libcrun_container_t *container, const char *source, int targetfd,
          const char *target, const char *fstype, unsigned long mountflags, const void *data,
          int label_how, libcrun_error_t *err)
{
  cleanup_free char *data_with_label = NULL;
  const char *real_target = target;
  bool single_instance = false;
  proc_fd_path_t target_buffer;
  bool needs_remount = false;
  cleanup_close int fd = -1;
  const char *label = NULL;
  int ret = 0;

#define ALL_PROPAGATIONS_NO_REC (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)
#define ALL_PROPAGATIONS (MS_REC | ALL_PROPAGATIONS_NO_REC)

  if (container->container_def->linux && container->container_def->linux->mount_label)
    label = container->container_def->linux->mount_label;
  else
    label_how = LABEL_NONE;

  if (targetfd >= 0)
    {
      get_proc_self_fd_path (target_buffer, targetfd);

      real_target = target_buffer;
    }

  if (label_how == LABEL_MOUNT)
    {
      const char *context_type = get_selinux_context_type (container);

      ret = add_selinux_mount_label (&data_with_label, data, label, context_type, err);
      if (ret < 0)
        return ret;
      data = data_with_label;
    }

  if ((fstype && fstype[0]) || (mountflags & MS_BIND))
    {
      unsigned long flags = mountflags & ~(ALL_PROPAGATIONS_NO_REC | MS_RDONLY);

      ret = mount (source, real_target, fstype, flags, data);
      if (UNLIKELY (ret < 0))
        {
          int saved_errno = errno;

          if ((mountflags & MS_RDONLY) && targetfd > 0 && fstype && strcmp (fstype, "sysfs") == 0)
            {
              /* If we are running in an user namespace, just bind mount /sys if creating
                 sysfs failed.  */
              ret = check_running_in_user_namespace (err);
              if (UNLIKELY (ret < 0))
                return ret;

              if (ret > 0)
                {
                  cleanup_close int mountfd = -1;

                  if (! has_mount_for (container, "/sys/fs/cgroup"))
                    {
                      ret = mount ("/sys", real_target, NULL, MS_BIND | MS_REC, NULL);
                      if (UNLIKELY (ret < 0))
                        return crun_make_error (err, errno, "bind mount `/sys` from the host");

                      return do_masked_or_readonly_path (container, "/sys/fs/cgroup", false, false, err);
                    }

                  mountfd = get_bind_mount (-1, "/sys", true, true, err);
                  if (UNLIKELY (mountfd < 0))
                    return mountfd;

                  ret = fs_move_mount_to (mountfd, targetfd, NULL);
                  if (UNLIKELY (ret < 0))
                    return crun_make_error (err, errno, "move mount to `%s`", real_target);

                  return 0;
                }
            }

          return crun_make_error (err, saved_errno, "mount `%s` to `%s`", source, target);
        }

      if (targetfd >= 0)
        {
          /* We need to reopen the path as the previous targetfd is underneath the new mountpoint.  */
          fd = open_mount_target (container, target, err);
          if (UNLIKELY (fd < 0))
            return fd;

#ifdef HAVE_FGETXATTR
          if (label_how == LABEL_XATTR)
            {
              proc_fd_path_t proc_file;

              get_proc_self_fd_path (proc_file, fd);

              /* We need to go through the proc_file since fd itself is opened as O_PATH.  */
              (void) setxattr (proc_file, "security.selinux", label, strlen (label), 0);
            }
#endif

          targetfd = fd;
          get_proc_self_fd_path (target_buffer, targetfd);
          real_target = target_buffer;
        }
    }

  if (mountflags & ALL_PROPAGATIONS)
    {
      unsigned long rec = mountflags & MS_REC;
      unsigned long propagation = mountflags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE);

      if (propagation)
        {
          ret = mount (NULL, real_target, NULL, rec | propagation, NULL);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "set propagation for `%s`", target);
        }
    }

  if (mountflags & (MS_BIND | MS_RDONLY))
    needs_remount = true;

  if (data && fstype && strcmp (fstype, "proc") == 0)
    {
      single_instance = true;
      needs_remount = true;
    }

  if (needs_remount)
    {
      unsigned long remount_flags = MS_REMOUNT | (single_instance ? 0 : MS_BIND) | (mountflags & ~ALL_PROPAGATIONS);

      if ((remount_flags & MS_RDONLY) == 0)
        {
          ret = do_remount (fd, target, remount_flags, data, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          struct remount_s *r;
          if (fd < 0)
            {
              fd = dup (targetfd);
              if (UNLIKELY (fd < 0))
                return crun_make_error (err, errno, "dup `%d`", targetfd);
            }

          /* The remount owns the fd.  */
          r = make_remount (get_and_reset (&fd), target, remount_flags, data, get_private_data (container)->remounts);
          get_private_data (container)->remounts = r;
        }
    }

  return ret;
}

static void
try_umount (int targetfd, const char *target)
{
  const char *real_target = target;
  proc_fd_path_t target_buffer;

  if (targetfd >= 0)
    {
      /* Best effort cleanup for the tmpfs.  */
      get_proc_self_fd_path (target_buffer, targetfd);
      real_target = target_buffer;
    }
  umount2 (real_target, MNT_DETACH);
}

static bool
container_has_cgroupns (libcrun_container_t *container)
{
  bool has_cgroupns = false;

#if CLONE_NEWCGROUP
  has_cgroupns = get_private_data (container)->unshare_flags & CLONE_NEWCGROUP;
#endif

  return has_cgroupns;
}

static int
do_mount_cgroup_v2 (libcrun_container_t *container, int targetfd, const char *target, unsigned long mountflags,
                    const char *unified_cgroup_path, libcrun_error_t *err)
{
  int ret;
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  ret = do_mount (container, "cgroup2", targetfd, target, "cgroup2", mountflags, NULL, LABEL_NONE, err);
  if (UNLIKELY (ret < 0))
    {
      errno = crun_error_get_errno (err);
      if (errno == EPERM || errno == EBUSY)
        {
          const char *src_cgroup;

          crun_error_release (err);

          if (errno == EBUSY)
            {
              /* If we got EBUSY it means the cgroup file system is already mounted at the targetfd and we
                 cannot stack another one on top of it.  Place a tmpfs in the middle, then try again.  */
              ret = do_mount (container, "tmpfs", targetfd, target, "tmpfs", 0, "nr_blocks=1,nr_inodes=1", LABEL_NONE, err);
              if (LIKELY (ret == 0))
                {
                  ret = do_mount (container, "cgroup2", targetfd, target, "cgroup2", mountflags, NULL, LABEL_NONE, err);
                  if (LIKELY (ret == 0))
                    return ret;

                  /* Best-effort cleanup for the tmpfs, if it fails there is nothing to worry about.  */
                  try_umount (targetfd, target);
                }

              /* If the previous method failed, fall back to bind mounting the current cgroup.  */
              crun_error_release (err);
            }

          /* If everything else failed, bind mount from the current cgroup.  */
          src_cgroup = unified_cgroup_path && container_has_cgroupns (container) ? unified_cgroup_path : CGROUP_ROOT;
          return do_mount (container, src_cgroup, targetfd, target, NULL,
                           MS_BIND | mountflags, NULL, LABEL_NONE, err);
        }

      return ret;
    }

  return 0;
}

static int
do_mount_cgroup_systemd_v1 (libcrun_container_t *container, const char *source, int targetfd, const char *target,
                            unsigned long mountflags, libcrun_error_t *err)
{
  int ret;
  cleanup_close int fd = -1;
  const char *subsystem = "systemd";
  cleanup_free char *subsystem_path = NULL;
  cleanup_close int tmpfsdirfd = -1;

  mountflags = mountflags & ~MS_BIND;

  ret = do_mount (container, source, targetfd, target, "tmpfs", mountflags, "size=1024k", LABEL_NONE, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Get a reference to the newly created cgroup directory.  */
  tmpfsdirfd = open_mount_target (container, target, err);
  if (UNLIKELY (tmpfsdirfd < 0))
    return tmpfsdirfd;
  targetfd = tmpfsdirfd;

  ret = mkdirat (targetfd, subsystem, 0755);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mkdir `%s`", subsystem);

  fd = openat (targetfd, subsystem, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open `%s`", subsystem_path);

  ret = append_paths (&subsystem_path, err, target, subsystem, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  return do_mount (container, "cgroup", fd, subsystem_path, "cgroup", mountflags, "none,name=systemd,xattr", LABEL_NONE,
                   err);
}

static int
do_mount_cgroup_v1 (libcrun_container_t *container, const char *source, int targetfd, const char *target,
                    unsigned long mountflags, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *content = NULL;
  char *from;
  cleanup_close int tmpfsdirfd = -1;
  char *saveptr = NULL;

  ret = do_mount (container, source, targetfd, target, "tmpfs", mountflags & ~MS_RDONLY, "size=1024k", LABEL_MOUNT,
                  err);
  if (UNLIKELY (ret < 0))
    return ret;

  tmpfsdirfd = open_mount_target (container, target, err);
  if (UNLIKELY (tmpfsdirfd < 0))
    return tmpfsdirfd;
  targetfd = tmpfsdirfd;

  ret = read_all_file (PROC_SELF_CGROUP, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, 0, "invalid content from `%s`", PROC_SELF_CGROUP);

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *source_path = NULL;
      cleanup_free char *source_subsystem = NULL;
      cleanup_free char *subsystem_path = NULL;
      char *subpath, *subsystem, *subsystem_fqn, *it;
      cleanup_close int subsystemfd = -1;
      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      if (subsystem[0] == '\0')
        continue;

      /* subsystem_fqn includes name= for named hierarchies.  */
      subsystem_fqn = subsystem;

      it = strstr (subsystem, "name=");
      if (it)
        subsystem = it + 5;

      if (strcmp (subsystem, "net_prio,net_cls") == 0)
        subsystem = "net_cls,net_prio";
      if (strcmp (subsystem, "cpuacct,cpu") == 0)
        subsystem = "cpu,cpuacct";

      ret = append_paths (&source_subsystem, err, CGROUP_ROOT, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      /* if there is already a mount specified, do not add a default one.  */
      if (has_mount_for (container, source_subsystem))
        continue;

      ret = append_paths (&source_path, err, source_subsystem, subpath, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&subsystem_path, err, target, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = mkdirat (targetfd, subsystem, 0755);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "mkdir `%s`", subsystem_path);

      subsystemfd = openat (targetfd, subsystem, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
      if (UNLIKELY (subsystemfd < 0))
        return crun_make_error (err, errno, "open `%s`", subsystem_path);

      if (container_has_cgroupns (container))
        {
          ret = do_mount (container, source_path, subsystemfd, subsystem_path, "cgroup", mountflags, subsystem_fqn,
                          LABEL_NONE, err);
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
      else
        {
          ret = do_mount (container, source_path, subsystemfd, subsystem_path, NULL, MS_BIND | mountflags, NULL,
                          LABEL_NONE, err);
          if (UNLIKELY (ret < 0))
            {
              if (crun_error_get_errno (err) != ENOENT)
                return ret;

              crun_error_release (err);

              /* We might already be in a container.  Mount the source subsystem.  */
              ret = do_mount (container, source_subsystem, subsystemfd, subsystem_path, NULL, MS_BIND | mountflags,
                              NULL, LABEL_NONE, err);
              if (UNLIKELY (ret < 0))
                {
                  /* If it still fails with ENOENT, ignore the error as the controller might have been
                     dropped and doesn't exist.  */
                  if (crun_error_get_errno (err) != ENOENT)
                    return ret;

                  crun_error_release (err);
                }
            }
        }
    }

  ret = libcrun_cgroups_create_symlinks (targetfd, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
do_mount_cgroup (libcrun_container_t *container, const char *source, int targetfd, const char *target,
                 unsigned long mountflags, const char *unified_cgroup_path, libcrun_error_t *err)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      return do_mount_cgroup_v2 (container, targetfd, target, mountflags, unified_cgroup_path, err);
    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      return do_mount_cgroup_v1 (container, source, targetfd, target, mountflags, err);
    }

  return crun_make_error (err, 0, "unknown cgroup mode `%d`", cgroup_mode);
}

struct device_s needed_devs[] = { { "/dev/null", "c", 1, 3, 0666, 0, 0 },
                                  { "/dev/zero", "c", 1, 5, 0666, 0, 0 },
                                  { "/dev/full", "c", 1, 7, 0666, 0, 0 },
                                  { "/dev/tty", "c", 5, 0, 0666, 0, 0 },
                                  { "/dev/random", "c", 1, 8, 0666, 0, 0 },
                                  { "/dev/urandom", "c", 1, 9, 0666, 0, 0 },
                                  {} };

/* Check if the specified path is a direct child of /dev.  If it is
 return a pointer to the basename.  */
static const char *
relative_path_under_dev (const char *path)
{
  if (path[0] != '/')
    return path;
  if (strncmp (path, "/dev/", 5) == 0)
    {
      if (strchr (path + 5, '/'))
        return NULL;
      return path + 5;
    }
  return NULL;
}

int
libcrun_create_dev (libcrun_container_t *container, int devfd, int srcfd,
                    struct device_s *device, bool binds, bool ensure_parent_dir,
                    libcrun_error_t *err)
{
  int ret;
  dev_t dev;
  mode_t type = (device->type[0] == 'b') ? S_IFBLK : ((device->type[0] == 'p') ? S_IFIFO : S_IFCHR);
  const char *fullname = device->path;
  cleanup_close int fd = -1;
  int rootfsfd = get_private_data (container)->rootfsfd;
  const char *rootfs = get_private_data (container)->rootfs;
  size_t rootfs_len = get_private_data (container)->rootfs_len;
  const char *rel_dev = relative_path_under_dev (device->path);

  if (binds)
    {
      cleanup_close int fd = -1;

      if (rel_dev)
        {
          fd = openat (devfd, rel_dev, O_NOFOLLOW | O_CLOEXEC | O_PATH | O_NONBLOCK);
          if (UNLIKELY (fd < 0))
            {
              if (errno == ENOENT)
                fd = openat (devfd, rel_dev, O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0700);

              if (UNLIKELY (fd < 0))
                return crun_make_error (err, errno, "create device `%s`", device->path);
            }
        }
      else
        {
          const char *rel_path = consume_slashes (device->path);

          fd = crun_safe_create_and_open_ref_at (false, rootfsfd, rootfs, rootfs_len, rel_path, 0755, err);
          if (UNLIKELY (fd < 0))
            return fd;
        }

      if (srcfd >= 0)
        {
          ret = syscall_move_mount (srcfd, "", fd, "", MOVE_MOUNT_T_EMPTY_PATH | MOVE_MOUNT_F_EMPTY_PATH);
          if (LIKELY (ret >= 0))
            return 0;
        }

      ret = do_mount (container, fullname, fd, device->path, NULL, MS_BIND | MS_PRIVATE | MS_NOEXEC | MS_NOSUID, NULL, LABEL_MOUNT, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      proc_fd_path_t fd_buffer;

      dev = makedev (device->major, device->minor);

      /* Check whether the path is directly under /dev.  Since we already have an open fd to /dev and mknodat(2)
         fails when the destination already exists or is a symlink, it is safe to use it directly.
         If it is not a direct child, then first get a fd to the dirfd.
      */
      if (rel_dev)
        {
          ret = mknodat (devfd, rel_dev, device->mode | type, dev);
          /* We don't fail when the file already exists.  */
          if (UNLIKELY (ret < 0 && errno == EEXIST))
            return 0;
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "mknod `%s`", device->path);

          fd = safe_openat (devfd, rootfs, rootfs_len, rel_dev, O_PATH | O_CLOEXEC, 0, err);
          if (UNLIKELY (fd < 0))
            return fd;

          get_proc_self_fd_path (fd_buffer, fd);

          ret = chmod (fd_buffer, device->mode);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "fchmodat `%s`", device->path);

          ret = chown (fd_buffer, device->uid, device->gid); /* lgtm [cpp/toctou-race-condition] */
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "chown `%s`", device->path);
        }
      else
        {
          char *dirname;
          cleanup_free char *buffer = NULL;
          cleanup_close int dirfd = -1;
          char *basename, *tmp;

          buffer = xstrdup (device->path);
          dirname = buffer;

          tmp = strrchr (buffer, '/');
          *tmp = '\0';
          basename = tmp + 1;

          if (dirname[0] == '\0')
            dirfd = dup (rootfsfd);
          else
            {
              dirfd = safe_openat (rootfsfd, rootfs, rootfs_len, dirname,
                                   O_DIRECTORY | O_PATH | O_CLOEXEC, 0, err);
              if (dirfd < 0 && ensure_parent_dir)
                {
                  crun_error_release (err);

                  dirfd = crun_safe_create_and_open_ref_at (true, rootfsfd, rootfs,
                                                            rootfs_len, dirname, 0755, err);
                }
            }
          if (UNLIKELY (dirfd < 0))
            return dirfd;

          ret = mknodat (dirfd, basename, device->mode | type, dev);

          /* We don't fail when the file already exists.  */
          if (UNLIKELY (ret < 0 && errno == EEXIST))
            return 0;
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "mknod `%s`", device->path);

          fd = safe_openat (dirfd, rootfs, rootfs_len, basename, O_PATH | O_CLOEXEC, 0, err);
          if (UNLIKELY (fd < 0))
            return crun_make_error (err, errno, "open `%s`", device->path);

          get_proc_self_fd_path (fd_buffer, fd);

          ret = chmod (fd_buffer, device->mode);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "chmod `%s`", device->path);

          ret = chown (fd_buffer, device->uid, device->gid); /* lgtm [cpp/toctou-race-condition] */
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "chown `%s`", device->path);
        }
    }
  return 0;
}

struct symlink_s
{
  const char *path;
  const char *target;
  bool force;
};

static struct symlink_s symlinks[] = { { "/proc/self/fd", "fd", false },
                                       { "/proc/self/fd/0", "stdin", false },
                                       { "/proc/self/fd/1", "stdout", false },
                                       { "/proc/self/fd/2", "stderr", false },
                                       { "/proc/kcore", "core", false },
                                       { "pts/ptmx", "ptmx", true },
                                       { NULL, NULL, false } };

static int
create_missing_devs (libcrun_container_t *container, bool binds, libcrun_error_t *err)
{
  int ret;
  size_t i;
  struct device_s *it;
  cleanup_close int devfd = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  const char *rootfs = get_private_data (container)->rootfs;
  int rootfsfd = get_private_data (container)->rootfsfd;
  cleanup_close_map struct libcrun_fd_map *dev_fds = NULL;

  dev_fds = get_private_data (container)->dev_fds;
  get_private_data (container)->dev_fds = NULL;

  devfd = openat (rootfsfd, "dev", O_RDONLY | O_DIRECTORY);
  if (UNLIKELY (devfd < 0))
    return crun_make_error (err, errno, "open /dev directory in `%s`", rootfs);

  for (i = 0; i < def->linux->devices_len; i++)
    {
      struct device_s device = {
        def->linux->devices[i]->path,
        def->linux->devices[i]->type,
        def->linux->devices[i]->major,
        def->linux->devices[i]->minor,
        def->linux->devices[i]->file_mode,
        def->linux->devices[i]->uid,
        def->linux->devices[i]->gid,
      };

      if (! def->linux->devices[i]->file_mode_present)
        device.mode = 0666;
      ret = libcrun_create_dev (container, devfd, dev_fds->fds[i], &device, binds, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (it = needed_devs; it->path; it++)
    {
      /* make sure the parent directory exists only on the first iteration.  */
      ret = libcrun_create_dev (container, devfd, -1, it, binds, it == needed_devs, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (i = 0; symlinks[i].target; i++)
    {
    retry_symlink:
      ret = symlinkat (symlinks[i].path, devfd, symlinks[i].target);
      if (UNLIKELY (ret < 0))
        {
          int saved_errno = errno;

          if (errno == EEXIST && ! symlinks[i].force)
            continue;

          /* If the symlink should be forced, make sure to unlink any existing file at the same path.  */
          if (errno == EEXIST)
            {
            retry_unlink:
              ret = unlinkat (devfd, symlinks[i].target, 0);
              if (ret < 0 && errno == EISDIR)
                ret = unlinkat (devfd, symlinks[i].target, AT_REMOVEDIR);
              if (ret < 0 && errno == EBUSY)
                {
                  cleanup_close int tfd = openat (devfd, symlinks[i].target, O_CLOEXEC | O_PATH | O_NOFOLLOW);
                  if (tfd >= 0)
                    {
                      proc_fd_path_t procpath;

                      get_proc_self_fd_path (procpath, tfd);
                      if (umount2 (procpath, MNT_DETACH) == 0)
                        goto retry_unlink;
                    }
                }
              if (ret == 0)
                goto retry_symlink;
            }
          return crun_make_error (err, saved_errno, "creating symlink for `/dev/%s`", symlinks[i].target);
        }
    }

  if (container->container_def->process && container->container_def->process->terminal)
    {
      ret = crun_ensure_file_at (devfd, "console", 0620, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
do_masked_and_readonly_paths (libcrun_container_t *container, libcrun_error_t *err)
{
  size_t i;
  int ret;
  runtime_spec_schema_config_schema *def = container->container_def;

  for (i = 0; i < def->linux->masked_paths_len; i++)
    {
      ret = do_masked_or_readonly_path (container, def->linux->masked_paths[i], false, false, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  for (i = 0; i < def->linux->readonly_paths_len; i++)
    {
      ret = do_masked_or_readonly_path (container, def->linux->readonly_paths[i], true, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
do_pivot (libcrun_container_t *container, const char *rootfs, libcrun_error_t *err)
{
  int ret;
  cleanup_close int oldrootfd = open ("/", O_DIRECTORY | O_PATH);
  cleanup_close int newrootfd = open (rootfs, O_DIRECTORY | O_RDONLY);

  if (UNLIKELY (oldrootfd < 0))
    return crun_make_error (err, errno, "open `/`");
  if (UNLIKELY (newrootfd < 0))
    return crun_make_error (err, errno, "open `%s`", rootfs);

  ret = fchdir (newrootfd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fchdir `%s`", rootfs);

  ret = pivot_root (".", ".");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pivot_root");

  ret = fchdir (oldrootfd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fchdir `%s`", rootfs);

  ret = do_mount (container, NULL, -1, ".", NULL, MS_REC | MS_PRIVATE, NULL, LABEL_MOUNT, err);
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
  } while (ret == 0);

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
  if (strcmp (destination, "/dev/cgroup") == 0 || strcmp (destination, "/sys/fs/cgroup") == 0)
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

static char *
append_mode_if_missing (char *data, const char *mode)
{
  char *new_data;
  bool append;

  if (data != NULL && strstr (data, "mode="))
    return data;

  append = data != NULL && data[0] != '\0';

  if (append)
    xasprintf (&new_data, "%s,%s", data, mode);
  else
    new_data = xstrdup (mode);

  free (data);

  return new_data;
}

static const char *
get_force_cgroup_v1_annotation (libcrun_container_t *container)
{
  return find_annotation (container, "run.oci.systemd.force_cgroup_v1");
}

static int
do_mounts (libcrun_container_t *container, int rootfsfd, const char *rootfs, const char *unified_cgroup_path, libcrun_error_t *err)
{
  size_t i;
  int ret;
  runtime_spec_schema_config_schema *def = container->container_def;
  size_t rootfs_len = get_private_data (container)->rootfs_len;
  const char *systemd_cgroup_v1 = get_force_cgroup_v1_annotation (container);
  cleanup_close_map struct libcrun_fd_map *mount_fds = NULL;

  mount_fds = get_private_data (container)->mount_fds;
  get_private_data (container)->mount_fds = NULL;

  for (i = 0; i < def->mounts_len; i++)
    {
      const char *target = consume_slashes (def->mounts[i]->destination);
      cleanup_free char *data = NULL;
      char *type;
      char *source;
      unsigned long flags = 0;
      unsigned long extra_flags = 0;
      int is_dir = 1;
      cleanup_close int copy_from_fd = -1;
      cleanup_close int targetfd = -1;
      bool mounted = false;
      bool is_sysfs_or_proc;
      uint64_t rec_clear = 0;
      uint64_t rec_set = 0;

      type = def->mounts[i]->type;

      if (def->mounts[i]->options == NULL)
        flags = get_default_flags (container, def->mounts[i]->destination, &data);
      else
        {
          size_t j;

          for (j = 0; j < def->mounts[i]->options_len; j++)
            flags |= get_mount_flags_or_option (def->mounts[i]->options[j], flags, &extra_flags, &data, &rec_clear, &rec_set);
        }

      if (type == NULL && (flags & MS_BIND) == 0)
        return crun_make_error (err, 0, "invalid mount type for `%s`", def->mounts[i]->destination);

      if (flags & MS_BIND)
        {
          if (path_is_slash_dev (def->mounts[i]->destination))
            get_private_data (container)->mount_dev_from_host = true;
          /* It is used only for error messages.  */
          type = "bind";
        }
      is_sysfs_or_proc = strcmp (type, "sysfs") == 0 || strcmp (type, "proc") == 0;

      if (def->mounts[i]->source && (flags & MS_BIND))
        {
          proc_fd_path_t proc_buf;
          const char *path = def->mounts[i]->source;
          if (mount_fds->fds[i] >= 0)
            {
              get_proc_self_fd_path (proc_buf, mount_fds->fds[i]);
              path = proc_buf;
            }

          is_dir = crun_dir_p (path, false, err);
          if (UNLIKELY (is_dir < 0))
            return is_dir;

          data = append_mode_if_missing (data, "mode=1755");
        }

      if (is_sysfs_or_proc)
        {
          /* Enforce sysfs and proc to be mounted on a regular directory.  */
          ret = openat (rootfsfd, target, O_NOFOLLOW | O_DIRECTORY);
          if (UNLIKELY (ret < 0))
            {
              if (errno == ENOENT)
                {
                  if (strchr (target, '/'))
                    return crun_make_error (err, 0, "invalid target `%s`: it must be mounted at the root", target);

                  ret = mkdirat (rootfsfd, target, 0755);
                  if (UNLIKELY (ret < 0))
                    return crun_make_error (err, errno, "cannot mkdir `%s`", target);

                  /* Try opening it again.  */
                  ret = openat (rootfsfd, target, O_NOFOLLOW | O_DIRECTORY);
                }
              else if (errno == ENOTDIR)
                return crun_make_error (err, errno, "the target `/%s` is invalid", target);

              if (ret < 0)
                return crun_make_error (err, errno, "cannot open `%s`", target);
            }

          targetfd = ret;
        }
      else
        {
          /* Make sure any other directory/file is created and take a O_PATH reference to it.  */
          ret = crun_safe_create_and_open_ref_at (is_dir, rootfsfd, rootfs, rootfs_len, target,
                                                  is_dir ? 01755 : 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;

          targetfd = ret;
        }

      if (extra_flags & OPTION_TMPCOPYUP)
        {
          if (strcmp (type, "tmpfs") != 0)
            return crun_make_error (err, 0, "tmpcopyup can be used only with tmpfs");

          /* targetfd is opened with O_PATH, reopen the fd so it can read.  */
          copy_from_fd = openat (targetfd, ".", O_RDONLY | O_DIRECTORY);
          if (UNLIKELY (copy_from_fd < 0))
            {
              if (errno != ENOTDIR)
                return crun_make_error (err, errno, "cannot reopen `%s`", target);

              crun_error_release (err);
            }
        }

      source = def->mounts[i]->source ? def->mounts[i]->source : type;

      /* Check if there is already a mount for the requested file system.  */
      if (mount_fds && mount_fds->fds[i] >= 0)
        {
          cleanup_close int mfd = get_and_reset (&(mount_fds->fds[i]));

          ret = fs_move_mount_to (mfd, targetfd, NULL);
          if (LIKELY (ret == 0))
            {
              /* Force no MS_BIND flag to not attempt again the bind mount.  */
              ret = do_mount (container, NULL, mfd, target, NULL, flags & ~MS_BIND, data, LABEL_NONE, err);
              if (UNLIKELY (ret < 0))
                return ret;
              mounted = true;
            }
        }

      if (! mounted)
        {
          if (systemd_cgroup_v1 && strcmp (def->mounts[i]->destination, systemd_cgroup_v1) == 0)
            {
              /* Override the cgroup mount with a single named cgroup name=systemd.  */
              ret = do_mount_cgroup_systemd_v1 (container, source, targetfd, target, flags, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          else if (strcmp (type, "cgroup") == 0)
            {
              ret = do_mount_cgroup (container, source, targetfd, target, flags, unified_cgroup_path, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          else
            {
              int label_how = LABEL_MOUNT;

              if (is_sysfs_or_proc)
                label_how = LABEL_NONE;
              else if (strcmp (type, "mqueue") == 0)
                label_how = LABEL_XATTR;

              ret = do_mount (container, source, targetfd, target, type, flags, data, label_how, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
        }

      if (copy_from_fd >= 0)
        {
          int destfd, tmpfd;

          destfd = safe_openat (rootfsfd, rootfs, rootfs_len, target, O_DIRECTORY, 0, err);
          if (UNLIKELY (destfd < 0))
            return crun_make_error (err, errno, "open target to write for tmpcopyup");

          /* take ownership for the fd.  */
          tmpfd = get_and_reset (&copy_from_fd);

          ret = copy_recursive_fd_to_fd (tmpfd, destfd, target, target, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (rec_clear || rec_set)
        {
          cleanup_close int dfd = -1;

          dfd = safe_openat (rootfsfd, rootfs, rootfs_len, target, O_DIRECTORY, 0, err);
          if (UNLIKELY (dfd < 0))
            return crun_make_error (err, errno, "open mount target `/%s`", target);

          ret = do_mount_setattr (target, dfd, rec_clear, rec_set, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  return 0;
}

/*
 * libcrun_container_do_bind_mount
 *
 *  Allows external plugins and handlers to perform bind `mounts` on container.
 *  returns: 0 if successful anything else states `error` and configures `err` with relevant error.
 */
int
libcrun_container_do_bind_mount (libcrun_container_t *container, char *mount_source, char *mount_destination, char **mount_options, size_t mount_options_len, libcrun_error_t *err)
{
  int ret, rootfsfd;
  size_t rootfs_len = get_private_data (container)->rootfs_len;

  const char *target = consume_slashes (mount_destination);
  cleanup_free char *data = NULL;
  unsigned long flags = 0;
  unsigned long extra_flags = 0;
  cleanup_close int targetfd = -1;
  int is_dir = 1;
  uint64_t rec_clear = 0;
  uint64_t rec_set = 0;
  const char *rootfs = get_private_data (container)->rootfs;
  rootfsfd = get_private_data (container)->rootfsfd;

  if ((rootfsfd < 0) || (rootfs == NULL))
    return crun_make_error (err, 0, "invalid rootfs state while performing bind mount from external plugin or handler");

  if (mount_options == NULL)
    flags = get_default_flags (container, mount_destination, &data);
  else
    {
      size_t j;

      for (j = 0; j < mount_options_len; j++)
        flags |= get_mount_flags_or_option (mount_options[j], flags, &extra_flags, &data, &rec_clear, &rec_set);
    }

  if (path_is_slash_dev (mount_destination))
    get_private_data (container)->mount_dev_from_host = true;

  if (mount_source && (flags & MS_BIND))
    {
      is_dir = crun_dir_p (mount_source, false, err);
      if (UNLIKELY (is_dir < 0))
        return is_dir;

      data = append_mode_if_missing (data, "mode=1755");
    }

  /* Make sure any other directory/file is created and take a O_PATH reference to it.  */
  ret = crun_safe_create_and_open_ref_at (is_dir, rootfsfd, rootfs, rootfs_len, target,
                                          is_dir ? 01755 : 0755, err);
  if (UNLIKELY (ret < 0))
    return ret;

  targetfd = ret;

  int label_how = LABEL_MOUNT;
  ret = do_mount (container, mount_source, targetfd, target, "bind", flags, data, label_how, err);
  if (UNLIKELY (ret < 0))
    return ret;

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
  int ret;

  if (container && get_private_data (container)->host_notify_socket_path)
    {
      const char *parent_dir;

      parent_dir = get_private_data (container)->host_notify_socket_path;

      ret = append_paths (&host_notify_socket_path, err, parent_dir, "notify", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      host_path = host_notify_socket_path;
    }

  *notify_socket_out = -1;

  if (host_path == NULL)
    {
      state_dir = libcrun_get_state_directory (context->state_root, context->id);

      ret = append_paths (&host_notify_socket_path, err, state_dir, "notify/notify", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      host_path = host_notify_socket_path;
    }

  notify_fd = open_unix_domain_socket (host_path, 1, err);
  if (UNLIKELY (notify_fd < 0))
    return notify_fd;

  if (UNLIKELY (chmod (host_path, 0777) < 0))
    return crun_make_error (err, errno, "chmod `%s`", host_path);

#  ifdef HAVE_FGETXATTR
  if (container && container->container_def->linux && container->container_def->linux->mount_label)
    {
      /* Ignore the error, the worse that can happen is that the container fails to notify it is ready.  */
      (void) setxattr (host_path, "security.selinux", container->container_def->linux->mount_label,
                       strlen (container->container_def->linux->mount_label), 0);
    }
#  endif

  *notify_socket_out = get_and_reset (&notify_fd);
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
  cleanup_free char *container_notify_socket_path = NULL;
  cleanup_free char *state_dir = libcrun_get_state_directory (container->context->state_root, container->context->id);
  uid_t container_root_uid = -1;
  gid_t container_root_gid = -1;
  int notify_socket_tree_fd;

  if (notify_socket == NULL)
    return 0;

  ret = append_paths (&container_notify_socket_path, err, rootfs, notify_socket, "notify", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&host_notify_socket_path, err, state_dir, "notify", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = mkdir (host_notify_socket_path, 0700);
  if (ret < 0)
    return crun_make_error (err, errno, "mkdir `%s`", host_notify_socket_path);

  if (get_private_data (container)->unshare_flags & CLONE_NEWUSER)
    {
      get_root_in_the_userns (container->container_def, 0, 0, &container_root_uid, &container_root_gid);
      if (container_root_uid != ((uid_t) -1) && container_root_gid != ((gid_t) -1))
        {
          ret = chown (host_notify_socket_path, container_root_uid, container_root_gid);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "chown `%d:%d` `%s`", container_root_uid, container_root_gid,
                                    host_notify_socket_path);
        }
    }

  notify_socket_tree_fd = syscall_open_tree (AT_FDCWD, host_notify_socket_path, OPEN_TREE_CLONE | AT_RECURSIVE);
  if (notify_socket_tree_fd >= 0)
    /* open_tree worked */
    get_private_data (container)->notify_socket_tree_fd = notify_socket_tree_fd;
  else if (errno == EPERM)
    /* this can happen when trying to run a rootless container; this function is called
       in the original namespace where the caller is _not_ CAP_SYS_ADMIN - in that case,
       do nothing, because the bind mount of host_notify_socket_path directly should succeed
       since it will be readable by the container user. */
    ;
  else if (errno == ENOSYS)
    /* if open_tree(2) is not available, do nothing; we will try mount(2) in do_finalize_notify_socket */
    ;
  else
    /* some other error */
    return crun_make_error (err, errno, "open_tree `%s`", host_notify_socket_path);

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
  cleanup_free char *host_notify_socket_path = NULL;
  cleanup_free char *container_notify_socket_path = NULL;
  cleanup_free char *container_notify_socket_path_dir_alloc = NULL;
  char *container_notify_socket_path_dir = NULL;
  cleanup_close int notify_socket_tree_fd = -1;
  int did_mount_with_move_mount = 0;

  host_notify_socket_path = get_private_data (container)->host_notify_socket_path;
  get_private_data (container)->host_notify_socket_path = NULL;

  container_notify_socket_path = get_private_data (container)->container_notify_socket_path;
  get_private_data (container)->container_notify_socket_path = NULL;

  if (host_notify_socket_path == NULL || container_notify_socket_path == NULL)
    return 0;

  container_notify_socket_path_dir_alloc = xstrdup (container_notify_socket_path);
  container_notify_socket_path_dir = dirname (container_notify_socket_path_dir_alloc);

  ret = crun_ensure_directory (container_notify_socket_path_dir, 0755, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  notify_socket_tree_fd = get_private_data (container)->notify_socket_tree_fd;
  /* the FD will be unconditionally closed at the end of this function due to cleanup_close above */
  get_private_data (container)->notify_socket_tree_fd = -1;

  if (notify_socket_tree_fd >= 0)
    {
      ret = syscall_move_mount (notify_socket_tree_fd, "", AT_FDCWD, container_notify_socket_path_dir,
                                MOVE_MOUNT_F_EMPTY_PATH);
      if (ret >= 0)
        /* if move_mount(2) worked, make sure we don't try mount(2) */
        did_mount_with_move_mount = 1;
      else if (errno == ENOSYS)
        /* do nothing; we will try mount(2) next */
        ;
      else
        return crun_make_error (err, errno, "move_mount `%d` -> `%s`", notify_socket_tree_fd,
                                container_notify_socket_path_dir);
    }

  if (! did_mount_with_move_mount)
    {
      ret = do_mount (container, host_notify_socket_path, -1, container_notify_socket_path_dir, NULL,
                      MS_BIND | MS_REC | MS_PRIVATE, NULL, LABEL_MOUNT, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

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
      return crun_make_error (err, errno, "make `%s` private", tmp);
    }
  return 0;
}

int
libcrun_set_mounts (struct container_entrypoint_s *entrypoint_args, libcrun_container_t *container, const char *rootfs, set_mounts_cb_t cb, void *cb_data, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_free char *unified_cgroup_path = NULL;
  cleanup_close int rootfsfd_cleanup = -1;
  unsigned long rootfs_propagation = 0;
  int rootfsfd = -1;
  int cgroup_mode;
  int is_user_ns = 0;
  int ret = 0;

  if (rootfs == NULL || def->mounts == NULL)
    return 0;

  if (def->linux->rootfs_propagation)
    rootfs_propagation = get_mount_flags (def->linux->rootfs_propagation, 0, NULL, NULL, NULL, NULL);

  if ((rootfs_propagation & (MS_SHARED | MS_SLAVE | MS_PRIVATE | MS_UNBINDABLE)) == 0)
    rootfs_propagation = MS_REC | MS_PRIVATE;

  get_private_data (container)->rootfs_propagation = rootfs_propagation;

  if (get_private_data (container)->unshare_flags & CLONE_NEWNS)
    {
      ret = do_mount (container, NULL, -1, "/", NULL, rootfs_propagation, NULL, LABEL_MOUNT, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = make_parent_mount_private (rootfs, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_mount (container, rootfs, -1, rootfs, NULL, MS_BIND | MS_REC | MS_PRIVATE, NULL, LABEL_MOUNT, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (rootfs == NULL)
    rootfsfd = AT_FDCWD;
  else
    {
      rootfsfd = rootfsfd_cleanup = open (rootfs, O_PATH | O_CLOEXEC);
      if (UNLIKELY (rootfsfd < 0))
        return crun_make_error (err, errno, "open `%s`", rootfs);
    }

  get_private_data (container)->rootfs = rootfs;
  get_private_data (container)->rootfsfd = rootfsfd;
  get_private_data (container)->rootfs_len = rootfs ? strlen (rootfs) : 0;

  // configure handler mounts
  ret = libcrun_container_notify_handler (entrypoint_args, HANDLER_CONFIGURE_MOUNTS, container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "failed configuring mounts for handler at phase: HANDLER_CONFIGURE_MOUNTS");

  if (def->root->readonly)
    {
      struct remount_s *r;
      unsigned long remount_flags = MS_REMOUNT | MS_BIND | MS_RDONLY;
      int fd;

      fd = dup (rootfsfd);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "dup fd for `%s`", rootfs);

      r = make_remount (fd, rootfs, remount_flags, NULL, get_private_data (container)->remounts);
      get_private_data (container)->remounts = r;
    }

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      /* Read the cgroup path before we enter the cgroupns.  */
      ret = libcrun_get_current_unified_cgroup (&unified_cgroup_path, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_container_enter_cgroup_ns (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_mounts (container, rootfsfd, rootfs, unified_cgroup_path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  free (unified_cgroup_path);
  unified_cgroup_path = NULL;

  is_user_ns = (get_private_data (container)->unshare_flags & CLONE_NEWUSER);
  if (! is_user_ns)
    {
      is_user_ns = check_running_in_user_namespace (err);
      if (UNLIKELY (is_user_ns < 0))
        return is_user_ns;
    }

  if (! get_private_data (container)->mount_dev_from_host)
    {
      ret = create_missing_devs (container, is_user_ns ? true : false, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Notify the callback after all the mounts are ready but before making them read-only.  */
  if (cb)
    {
      ret = cb (cb_data, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = do_finalize_notify_socket (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process && def->process->cwd)
    {
      libcrun_error_t tmp_err = NULL;
      const char *rel_cwd = consume_slashes (def->process->cwd);
      /* Ignore errors here and let it fail later.  */
      (void) crun_safe_ensure_directory_at (rootfsfd, rootfs, strlen (rootfs),
                                            rel_cwd, 0755, &tmp_err);
      crun_error_release (&tmp_err);
    }

  ret = do_masked_and_readonly_paths (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = finalize_mounts (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // configure handler mounts for phase: HANDLER_CONFIGURE_AFTER_MOUNTS
  ret = libcrun_container_notify_handler (entrypoint_args, HANDLER_CONFIGURE_AFTER_MOUNTS, container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "failed configuring mounts for handler at phase: HANDLER_CONFIGURE_AFTER_MOUNTS");

  get_private_data (container)->rootfsfd = -1;

  return 0;
}

static int
umount_or_hide (const char *target, libcrun_error_t *err)
{
  int ret;

  ret = umount2 (target, MNT_DETACH);
  if (UNLIKELY (ret < 0))
    {
      int saved_errno = errno;

      /* If the umount2 failed with EINVAL then the mount could
         be locked.  Hide it by mounting a tmpfs on top of it.  */
      if (errno == EINVAL)
        {
          ret = mount (NULL, target, "tmpfs", 0, "size=0k");
          if (LIKELY (ret == 0))
            return 0;
        }

      return crun_make_error (err, saved_errno, "umount `%s`", target);
    }

  return ret;
}

static int
move_root (const char *rootfs, libcrun_error_t *err)
{
  int ret;

  ret = chdir (rootfs);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to `%s`", rootfs);

  ret = umount_or_hide ("/sys", err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = umount_or_hide ("/proc", err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = mount (rootfs, "/", "", MS_MOVE, "");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mount MS_MOVE to `/`");

  ret = chroot (".");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chroot to `%s`", rootfs);

  ret = chdir ("/");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to `%s`", rootfs);

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

      ret = do_mount (container, NULL, -1, "/", NULL, get_private_data (container)->rootfs_propagation, NULL,
                      LABEL_MOUNT, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = chroot (rootfs);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "chroot to `%s`", rootfs);
    }

  ret = chdir ("/");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to `/`");

  return 0;
}

/* If one of stdin, stdout, stderr are pointing to /dev/null on
 * the outside of the container, this moves it to /dev/null inside
 * of the container. This needs to run after pivot/chroot-ing. */
int
libcrun_reopen_dev_null (libcrun_error_t *err)
{
  struct stat dev_null;
  struct stat statbuf;
  cleanup_close int fd;
  int i;

  /* Open /dev/null inside of the container. */
  fd = open ("/dev/null", O_RDWR);
  if (UNLIKELY (fd == -1))
    return crun_make_error (err, errno, "failed open()ing `/dev/null`");

  if (UNLIKELY (fstat (fd, &dev_null) == -1))
    return crun_make_error (err, errno, "failed stat()ing `/dev/null`");

  for (i = 0; i <= 2; i++)
    {
      if (UNLIKELY (fstat (i, &statbuf) == -1))
        return crun_make_error (err, errno, "failed stat()ing fd `%d`", i);
      if (statbuf.st_rdev == dev_null.st_rdev)
        {
          /* This FD is pointing to /dev/null. Point it to /dev/null inside
           * of the container. */
          if (UNLIKELY (dup2 (fd, i) == -1))
            return crun_make_error (err, errno, "failed dup2()ing `%d`", i);
        }
    }
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
  return uidgidmap_helper ("newgidmap", pid, map_file, err);
}

static int
newuidmap (pid_t pid, char *map_file, libcrun_error_t *err)
{
  return uidgidmap_helper ("newuidmap", pid, map_file, err);
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
libcrun_container_setgroups (libcrun_container_t *container,
                             runtime_spec_schema_config_schema_process *process,
                             libcrun_error_t *err)
{
  gid_t *additional_gids = NULL;
  size_t additional_gids_len = 0;
  int can_do_setgroups;
  int ret;

  if (process != NULL && process->user != NULL)
    {
      additional_gids = process->user->additional_gids;
      additional_gids_len = process->user->additional_gids_len;
    }

  can_do_setgroups = can_setgroups (container, err);
  if (UNLIKELY (can_do_setgroups < 0))
    return can_do_setgroups;

  if (can_do_setgroups == 0)
    return 0;

  ret = setgroups (additional_gids_len, additional_gids);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setgroups");

  return 0;
}

int
libcrun_container_enter_cgroup_ns (libcrun_container_t *container, libcrun_error_t *err)
{
#if CLONE_NEWCGROUP
  if (get_private_data (container)->unshare_cgroupns)
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

// determine whether the uid/gid mappings only contain a single entry
// that maps the host uid/gid on the process->user->uid/gid
int
is_single_mapping (runtime_spec_schema_defs_id_mapping **mappings, size_t len,
                   uint32_t host_id, uint32_t container_id)
{
  if (len != 1)
    return 0;

  if (mappings[0]->size != 1)
    return 0;

  if (mappings[0]->container_id != container_id || mappings[0]->host_id != host_id)
    return 0;

  return 1;
}

int
libcrun_set_usernamespace (libcrun_container_t *container, pid_t pid, libcrun_error_t *err)
{
  cleanup_free char *uid_map_file = NULL;
  cleanup_free char *gid_map_file = NULL;
  cleanup_free char *uid_map = NULL;
  cleanup_free char *gid_map = NULL;
  size_t uid_map_len = 0, gid_map_len = 0;
  int ret = 0;
  runtime_spec_schema_config_schema *def = container->container_def;

  if ((get_private_data (container)->unshare_flags & CLONE_NEWUSER) == 0)
    return 0;

  if (def->linux->uid_mappings_len)
    uid_map = format_mount_mappings (def->linux->uid_mappings, def->linux->uid_mappings_len, &uid_map_len);
  else
    {
      uid_map_len = format_default_id_mapping (&uid_map, container->container_uid, container->host_uid, container->host_uid, 1);
      if (uid_map == NULL)
        uid_map = format_mount_mapping (0, container->host_uid, container->host_uid + 1, &uid_map_len);
    }

  if (def->linux->gid_mappings_len)
    gid_map = format_mount_mappings (def->linux->gid_mappings, def->linux->gid_mappings_len, &gid_map_len);
  else
    {
      gid_map_len = format_default_id_mapping (&gid_map, container->container_gid, container->host_uid, container->host_gid, 0);
      if (gid_map == NULL)
        gid_map = format_mount_mapping (0, container->host_gid, container->host_gid + 1, &gid_map_len);
    }

  if (container->host_uid)
    ret = newgidmap (pid, gid_map, err);
  if (container->host_uid == 0 || ret < 0)
    {
      if (ret < 0)
        {
          if (! def->linux->uid_mappings_len)
            libcrun_warning ("unable to invoke `newgidmap`, will try creating a user namespace with single mapping as an alternative");
          crun_error_release (err);
        }

      xasprintf (&gid_map_file, "/proc/%d/gid_map", pid);
      ret = write_file (gid_map_file, gid_map, gid_map_len, err);
      if (ret < 0 && (! def->linux->gid_mappings_len || is_single_mapping (def->linux->gid_mappings, def->linux->gid_mappings_len, container->host_gid, container->container_gid)))
        {
          size_t single_mapping_len;
          cleanup_free char *single_mapping = NULL;
          crun_error_release (err);

          ret = deny_setgroups (container, pid, err);
          if (UNLIKELY (ret < 0))
            return ret;

          single_mapping = format_mount_mapping (container->container_gid, container->host_gid, 1, &single_mapping_len);

          ret = write_file (gid_map_file, single_mapping, single_mapping_len, err);
        }
    }
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->host_uid)
    ret = newuidmap (pid, uid_map, err);
  if (container->host_uid == 0 || ret < 0)
    {
      if (ret < 0)
        {
          if (! def->linux->uid_mappings_len)
            libcrun_warning ("unable to invoke `newuidmap`, will try creating a user namespace with single mapping as an alternative");
          crun_error_release (err);
        }

      xasprintf (&uid_map_file, "/proc/%d/uid_map", pid);
      ret = write_file (uid_map_file, uid_map, uid_map_len, err);
      if (ret < 0 && (! def->linux->uid_mappings_len || is_single_mapping (def->linux->uid_mappings, def->linux->uid_mappings_len, container->host_uid, container->container_uid)))
        {
          size_t single_mapping_len;
          cleanup_free char *single_mapping = NULL;
          crun_error_release (err);

          if (! get_private_data (container)->deny_setgroups)
            {
              ret = deny_setgroups (container, pid, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }

          single_mapping = format_mount_mapping (container->container_uid, container->host_uid, 1, &single_mapping_len);

          ret = write_file (uid_map_file, single_mapping, single_mapping_len, err);
        }
    }
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

#define CAP_TO_MASK_0(x) (1L << ((x) &31))
#define CAP_TO_MASK_1(x) CAP_TO_MASK_0 (x - 32)

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

static unsigned long cap_last_cap;

int
libcrun_init_caps (libcrun_error_t *err)
{
  const char *const cap_last_cap_file = "/proc/sys/kernel/cap_last_cap";
  cleanup_close int fd = -1;
  int ret;
  char buffer[16];
  fd = open (cap_last_cap_file, O_RDONLY);
  if (fd < 0)
    return crun_make_error (err, errno, "open `%s`", cap_last_cap_file);
  ret = TEMP_FAILURE_RETRY (read (fd, buffer, sizeof (buffer)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from `%s`", cap_last_cap_file);

  errno = 0;
  cap_last_cap = strtoul (buffer, NULL, 10);
  if (errno != 0)
    return crun_make_error (err, errno, "strtoul() from `%s`", cap_last_cap_file);
  return 0;
}

static int
set_required_caps (struct all_caps_s *caps, uid_t uid, gid_t gid, int no_new_privs, libcrun_error_t *err)
{
#ifdef HAVE_CAP
  unsigned long cap;
  int ret;
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[2] = { { 0 } };

  if (cap_last_cap == 0)
    return crun_make_error (err, 0, "internal error: max number of capabilities not initialized");

  for (cap = 0; cap <= cap_last_cap; cap++)
    if (! has_cap_on (cap, caps->bounding))
      {
        ret = prctl (PR_CAPBSET_DROP, cap, 0, 0, 0);
        if (UNLIKELY (ret < 0 && ! (errno == EINVAL)))
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
    return crun_make_error (err, errno, "error while setting `PR_SET_KEEPCAPS`");

  ret = setresgid (gid, gid, gid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot setresgid to `%d`", gid);

  ret = setresuid (uid, uid, uid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot setresuid to `%d`", uid);

  ret = capset (&hdr, data);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "capset");

#  ifdef PR_CAP_AMBIENT
  ret = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
  if (UNLIKELY (ret < 0 && ! (errno == EINVAL || errno == EPERM)))
    return crun_make_error (err, errno, "prctl reset ambient");

  for (cap = 0; cap <= cap_last_cap; cap++)
    if (has_cap_on (cap, caps->ambient))
      {
        ret = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
        if (UNLIKELY (ret < 0 && ! (errno == EINVAL || errno == EPERM)))
          return crun_make_error (err, errno, "prctl ambient raise");
      }
#  endif
#endif

  if (no_new_privs)
    if (UNLIKELY (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0))
      return crun_make_error (err, errno, "no new privs");

  return 0;
}

static int
read_caps (unsigned long caps[2], char **values, size_t len)
{
#ifdef HAVE_CAP
  size_t i;
  for (i = 0; i < len; i++)
    {
      cap_value_t cap;
      if (cap_from_name (values[i], &cap) < 0)
        {
          libcrun_warning ("unknown cap: `%s`", values[i]);
          continue;
        }
      if (cap < 32)
        caps[0] |= CAP_TO_MASK_0 (cap);
      else
        caps[1] |= CAP_TO_MASK_1 (cap);
    }
#else
  caps[0] = 0;
  caps[1] = 0;
#endif
  return 0;
}

int
libcrun_set_selinux_label (runtime_spec_schema_config_schema_process *proc, bool now, libcrun_error_t *err)
{
  if (proc->selinux_label)
    return set_selinux_label (proc->selinux_label, now, err);

  return 0;
}

int
libcrun_set_apparmor_profile (runtime_spec_schema_config_schema_process *proc, bool now, libcrun_error_t *err)
{
  if (proc->apparmor_profile)
    return set_apparmor_profile (proc->apparmor_profile, now, err);
  return 0;
}

int
libcrun_set_caps (runtime_spec_schema_config_schema_process_capabilities *capabilities, uid_t uid, gid_t gid,
                  int no_new_privileges, libcrun_error_t *err)
{
  struct all_caps_s caps = {};

  if (capabilities)
    {
      read_caps (caps.effective, capabilities->effective, capabilities->effective_len);
      read_caps (caps.inheritable, capabilities->inheritable, capabilities->inheritable_len);
      read_caps (caps.ambient, capabilities->ambient, capabilities->ambient_len);
      read_caps (caps.bounding, capabilities->bounding, capabilities->bounding_len);
      read_caps (caps.permitted, capabilities->permitted, capabilities->permitted_len);
    }
  return set_required_caps (&caps, uid, gid, no_new_privileges, err);
}

struct rlimit_s
{
  const char *name;
  int value;
};

struct rlimit_s rlimits[] = { { "RLIMIT_AS", RLIMIT_AS },
                              { "RLIMIT_CORE", RLIMIT_CORE },
                              { "RLIMIT_CPU", RLIMIT_CPU },
                              { "RLIMIT_DATA", RLIMIT_DATA },
                              { "RLIMIT_FSIZE", RLIMIT_FSIZE },
                              { "RLIMIT_LOCKS", RLIMIT_LOCKS },
                              { "RLIMIT_MEMLOCK", RLIMIT_MEMLOCK },
                              { "RLIMIT_MSGQUEUE", RLIMIT_MSGQUEUE },
                              { "RLIMIT_NICE", RLIMIT_NICE },
                              { "RLIMIT_NOFILE", RLIMIT_NOFILE },
                              { "RLIMIT_NPROC", RLIMIT_NPROC },
                              { "RLIMIT_RSS", RLIMIT_RSS },
                              { "RLIMIT_RTPRIO", RLIMIT_RTPRIO },
                              { "RLIMIT_RTTIME", RLIMIT_RTTIME },
                              { "RLIMIT_SIGPENDING", RLIMIT_SIGPENDING },
                              { "RLIMIT_STACK", RLIMIT_STACK },
                              { NULL, 0 } };

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
libcrun_set_rlimits (runtime_spec_schema_config_schema_process_rlimits_element **new_rlimits, size_t len,
                     libcrun_error_t *err)
{
  size_t i;
  for (i = 0; i < len; i++)
    {
      struct rlimit limit;
      char *type = new_rlimits[i]->type;
      int resource = get_rlimit_resource (type);
      if (UNLIKELY (resource < 0))
        return crun_make_error (err, 0, "invalid rlimit `%s`", type);
      limit.rlim_cur = new_rlimits[i]->soft;
      limit.rlim_max = new_rlimits[i]->hard;
      if (UNLIKELY (setrlimit (resource, &limit) < 0))
        return crun_make_error (err, errno, "setrlimit `%s`", type);
    }
  return 0;
}

int
libcrun_set_hostname (libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int has_uts = get_private_data (container)->unshare_flags & CLONE_NEWUTS;
  int ret;
  if (def->hostname == NULL || def->hostname[0] == '\0')
    return 0;
  if (! has_uts)
    return crun_make_error (err, 0, "hostname requires the UTS namespace");
  ret = sethostname (def->hostname, strlen (def->hostname));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sethostname");
  return 0;
}

int
libcrun_set_domainname (libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int has_uts = get_private_data (container)->unshare_flags & CLONE_NEWUTS;
  int ret;
  if (is_empty_string (def->domainname))
    return 0;
  if (! has_uts)
    return crun_make_error (err, 0, "domainname requires the UTS namespace");
  ret = setdomainname (def->domainname, strlen (def->domainname));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setdomainname");
  return 0;
}

int
libcrun_set_oom (libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close int fd = -1;
  int ret;
  char oom_buffer[16];
  if (def->process == NULL || def->process->oom_score_adj == 0)
    return 0;
  sprintf (oom_buffer, "%i", def->process->oom_score_adj);
  fd = open ("/proc/self/oom_score_adj", O_RDWR);
  if (fd < 0)
    return crun_make_error (err, errno, "open `/proc/self/oom_score_adj`");
  ret = TEMP_FAILURE_RETRY (write (fd, oom_buffer, strlen (oom_buffer)));
  if (ret < 0)
    return crun_make_error (err, errno, "write to `/proc/self/oom_score_adj`");
  return 0;
}

const char *sysctlRequiringIPC[] = {
  "kernel/msgmax",
  "kernel/msgmnb",
  "kernel/msgmni",
  "kernel/sem",
  "kernel/shmall",
  "kernel/shmmax",
  "kernel/shmmni",
  "kernel/shm_rmid_forced",
  NULL
};

static int
validate_sysctl (const char *original_key, const char *original_value, const char *name, unsigned long namespaces_created, runtime_spec_schema_config_schema *def, libcrun_error_t *err)
{
  const char *namespace = "";

  name = consume_slashes (name);

  if (has_prefix (name, "fs/mqueue/"))
    {
      if (namespaces_created & CLONE_NEWIPC)
        return 0;

      namespace = "IPC";
      goto fail;
    }

  if (has_prefix (name, "kernel/"))
    {
      size_t i;

      for (i = 0; sysctlRequiringIPC[i]; i++)
        if (strcmp (sysctlRequiringIPC[i], name) == 0)
          {
            if (namespaces_created & CLONE_NEWIPC)
              return 0;

            namespace = "IPC";
            goto fail;
          }

      if (strcmp (name, "kernel/domainname") == 0)
        {
          // Value of sysctl `kernel/domainname` is going to
          // conflict with already set field `domainname` in
          // OCI spec, in such scenario crun will fail to prevent
          // unexpected behaviour for end user.
          if (! is_empty_string (def->domainname) && (strcmp (original_value, def->domainname) != 0))
            return crun_make_error (err, 0, "the sysctl `%s` conflicts with OCI field `domainname`", original_key);

          if (namespaces_created & CLONE_NEWUTS)
            return 0;

          namespace = "UTS";
          goto fail;
        }

      if (strcmp (name, "kernel/hostname") == 0)
        return crun_make_error (err, 0, "the sysctl `%s` conflicts with OCI field `hostname`", original_key);
    }
  if (has_prefix (name, "net/"))
    {
      if (namespaces_created & CLONE_NEWNET)
        return 0;

      namespace = "network";
      goto fail;
    }

  return crun_make_error (err, 0, "the sysctl `%s` is not namespaced", original_key);

fail:
  return crun_make_error (err, 0, "the sysctl `%s` requires a new %s namespace", original_key, namespace);
}

int
libcrun_set_sysctl (libcrun_container_t *container, libcrun_error_t *err)
{
  size_t i;
  cleanup_close int dirfd = -1;
  unsigned long namespaces_created = 0;
  runtime_spec_schema_config_schema *def = container->container_def;

  if (def->linux == NULL || def->linux->sysctl == NULL || def->linux->sysctl->len == 0)
    return 0;

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value;

      value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);

      namespaces_created |= value;
    }

  get_private_data (container);
  dirfd = open ("/proc/sys", O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open `/proc/sys`");

  for (i = 0; i < def->linux->sysctl->len; i++)
    {
      cleanup_free char *name = NULL;
      cleanup_close int fd = -1;
      int ret;
      char *it;

      name = xstrdup (def->linux->sysctl->keys[i]);
      for (it = name; *it; it++)
        if (*it == '.')
          *it = '/';

      ret = validate_sysctl (def->linux->sysctl->keys[i], def->linux->sysctl->values[i], name, namespaces_created, def, err);
      if (UNLIKELY (ret < 0))
        return ret;

      fd = openat (dirfd, name, O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open `/proc/sys/%s`", name);

      ret = TEMP_FAILURE_RETRY (write (fd, def->linux->sysctl->values[i], strlen (def->linux->sysctl->values[i])));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write to `/proc/sys/%s`", name);
    }
  return 0;
}

static int
open_terminal (char **pty, runtime_spec_schema_config_schema_process *process, libcrun_error_t *err)
{
  cleanup_close int fd = -1;
  uid_t uid = 0;
  int ret;

  if (process && process->user)
    uid = process->user->uid;

  fd = libcrun_new_terminal (pty, err);
  if (UNLIKELY (fd < 0))
    return fd;

  ret = libcrun_set_stdio (*pty, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (uid)
    {
      ret = chown (*pty, uid, -1);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "chown `%s`", *pty);
    }

  ret = get_and_reset (&fd);
  return ret;
}

char *
libcrun_get_external_descriptors (libcrun_container_t *container)
{
  return get_private_data (container)->external_descriptors;
}

int
libcrun_save_external_descriptors (libcrun_container_t *container, pid_t pid, libcrun_error_t *err)
{
  const unsigned char *buf = NULL;
  yajl_gen gen = NULL;
  size_t buf_len;
  int ret;
  int i;

  gen = yajl_gen_alloc (NULL);
  if (gen == NULL)
    return crun_make_error (err, errno, "yajl_gen_alloc");

  ret = yajl_gen_array_open (gen);
  if (UNLIKELY (ret != yajl_gen_status_ok))
    goto yajl_error;

  /* Remember original stdin, stdout, stderr for container restore.  */
  for (i = 0; i < 3; i++)
    {
      proc_fd_path_t fd_path;
      char link_path[PATH_MAX];

      get_proc_fd_path (fd_path, pid, i);

      ret = readlink (fd_path, link_path, PATH_MAX - 1);
      if (UNLIKELY (ret < 0))
        {
          /* The fd could not exist.  */
          if (errno == ENOENT)
            {
              strcpy (link_path, "/dev/null");
              ret = 9; /* strlen ("/dev/null").  */
            }
          else
            {
              yajl_gen_free (gen);
              return crun_make_error (err, errno, "readlink `%s`", fd_path);
            }
        }
      link_path[ret] = 0;

      ret = yajl_gen_string (gen, YAJL_STR (link_path), ret);
      if (UNLIKELY (ret != yajl_gen_status_ok))
        goto yajl_error;
    }

  ret = yajl_gen_array_close (gen);
  if (UNLIKELY (ret != yajl_gen_status_ok))
    goto yajl_error;

  ret = yajl_gen_get_buf (gen, &buf, &buf_len);
  if (UNLIKELY (ret != yajl_gen_status_ok))
    goto yajl_error;

  if (buf)
    {
      char *b = xmalloc (buf_len + 1);
      memcpy (b, buf, buf_len);
      b[buf_len] = '\0';
      get_private_data (container)->external_descriptors = b;
    }

  yajl_gen_free (gen);

  return 0;

yajl_error:
  if (gen)
    yajl_gen_free (gen);
  return yajl_error_to_crun_error (ret, err);
}

int
libcrun_set_terminal (libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_free char *pty = NULL;
  cleanup_close int fd = -1;
  int ret;

  if (def->process == NULL || ! def->process->terminal)
    return 0;

  fd = open_terminal (&pty, def->process, err);
  if (UNLIKELY (fd < 0))
    return fd;

  if (def->process->console_size)
    {
      ret = libcrun_terminal_setup_size (0, def->process->console_size->height, def->process->console_size->width, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = do_mount (container, pty, -1, "/dev/console", NULL, MS_BIND, NULL, LABEL_MOUNT, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return get_and_reset (&fd);
}

static bool
read_error_from_sync_socket (int sync_socket_fd, int *error, char **str)
{
  cleanup_free char *b = NULL;
  size_t size;
  int code;
  int ret;

  if (*error == 0)
    {
      ret = TEMP_FAILURE_RETRY (read (sync_socket_fd, &code, sizeof (code)));
      if (UNLIKELY (ret < 0))
        return false;
      *error = code;
    }

  ret = TEMP_FAILURE_RETRY (read (sync_socket_fd, &size, sizeof (size)));
  if (UNLIKELY (ret < 0))
    return false;

  if (size == 0)
    return false;

  if (size > 1024)
    size = 1024;

  b = xmalloc (size + 1);
  ret = TEMP_FAILURE_RETRY (read (sync_socket_fd, b, size));
  if (UNLIKELY (ret < 0))
    return false;

  b[ret] = '\0';

  *str = b;
  b = NULL;
  return true;
}

static bool
send_error_to_sync_socket (int sync_socket_fd, bool has_fd, libcrun_error_t *err)
{
  size_t size;
  int ret;
  int code;
  char *msg;

  if (err == NULL || *err == NULL)
    return false;

  code = crun_error_get_errno (err);

  if (has_fd)
    {
      /* dummy terminal fd.  */
      ret = TEMP_FAILURE_RETRY (write (sync_socket_fd, "1", 1));
      if (UNLIKELY (ret < 0))
        return false;
    }

  ret = TEMP_FAILURE_RETRY (write (sync_socket_fd, &code, sizeof (code)));
  if (UNLIKELY (ret < 0))
    return false;

  msg = (*err)->msg;
  size = strlen (msg) + 1;
  ret = TEMP_FAILURE_RETRY (write (sync_socket_fd, &size, sizeof (size)));
  if (UNLIKELY (ret < 0))
    return false;

  ret = TEMP_FAILURE_RETRY (write (sync_socket_fd, msg, size));
  if (UNLIKELY (ret < 0))
    return false;

  return true;
}

static inline int
send_success_to_sync_socket (int sync_socket, libcrun_error_t *err)
{
  const int success = 0;
  int ret;

  ret = TEMP_FAILURE_RETRY (write (sync_socket, &success, sizeof (success)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to sync socket");

  return 0;
}

static __attribute__ ((noreturn)) void
send_error_to_sync_socket_and_die (int sync_socket_fd, bool has_terminal, libcrun_error_t *err)
{
  char *msg;

  if (err == NULL || *err == NULL)
    _exit (EXIT_FAILURE);

  if (! send_error_to_sync_socket (sync_socket_fd, has_terminal, err))
    {
      errno = crun_error_get_errno (err);
      msg = (*err)->msg;
      libcrun_fail_with_error (errno, "%s", msg);
    }
  _exit (EXIT_FAILURE);
}

static int
expect_success_from_sync_socket (int sync_fd, libcrun_error_t *err)
{
  cleanup_free char *err_str = NULL;
  int res = 1;
  int ret;

  ret = TEMP_FAILURE_RETRY (read (sync_fd, &res, sizeof (res)));
  if (UNLIKELY (ret != sizeof (res)))
    return crun_make_error (err, errno, "read status from sync socket");

  if (res == 0)
    return 0;

  if (read_error_from_sync_socket (sync_fd, &res, &err_str))
    return crun_make_error (err, res, "%s", err_str);

  return crun_make_error (err, 0, "read from sync socket");
}

static int
join_namespaces (runtime_spec_schema_config_schema *def, int *namespaces_to_join, int n_namespaces_to_join,
                 int *namespaces_to_join_index, bool ignore_join_errors, libcrun_error_t *err)
{
  int ret;
  int i;

  for (i = 0; i < n_namespaces_to_join; i++)
    {
      cleanup_free char *cwd = NULL;
      int orig_index = namespaces_to_join_index[i];
      int value;

      if (namespaces_to_join[i] < 0)
        continue;

      /* Skip the user namespace.  */
      value = libcrun_find_namespace (def->linux->namespaces[orig_index]->type);
      if (value == CLONE_NEWUSER)
        continue;

      if (value == CLONE_NEWNS)
        {
          cwd = getcwd (NULL, 0);
          if (UNLIKELY (cwd == NULL))
            return crun_make_error (err, errno, "cannot get current working directory");
        }

      ret = setns (namespaces_to_join[i], value);
      if (UNLIKELY (ret < 0))
        {
          if (ignore_join_errors)
            continue;
          return crun_make_error (err, errno, "cannot setns `%s`", def->linux->namespaces[orig_index]->path);
        }

      close_and_reset (&namespaces_to_join[i]);

      if (value == CLONE_NEWNS)
        {
          ret = chdir (cwd);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "chdir(.)");
        }
    }
  return 0;
}

#define MAX_NAMESPACES 10

struct init_status_s
{
  /* fd to the namespace to join.  */
  int fd[MAX_NAMESPACES + 1];
  /* Index into def->linux->namespaces.  */
  int index[MAX_NAMESPACES];
  /* CLONE_* value.  */
  int value[MAX_NAMESPACES];
  /* How many namespaces to join.  */
  size_t fd_len;

  bool join_pidns;
  bool join_ipcns;

  /* Must create the user namespace after joining
     some existing namespaces.  */
  bool delayed_userns_create;

  /* Need to fork again once in the container.  */
  bool must_fork;

  /* fd index for userns.  */
  int userns_index;
  /* def->linux->namespaces userns.  */
  int userns_index_origin;

  /* All namespaces created/joined by the container.  */
  int all_namespaces;

  /* What namespaces are still missing to be created.  */
  int namespaces_to_unshare;

  /* Index in fd[] for the pidns that must be joined before any
     other namespace.  */
  int idx_pidns_to_join_immediately;

  /* Index in fd[] for the timens that must be joined before any
     other namespace.  */
  int idx_timens_to_join_immediately;
};

void
cleanup_free_init_statusp (struct init_status_s *ns)
{
  size_t i;

  for (i = 0; i < ns->fd_len; i++)
    TEMP_FAILURE_RETRY (close (ns->fd[i]));
}

static int
configure_init_status (struct init_status_s *ns, libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  size_t i;

  for (i = 0; i < MAX_NAMESPACES + 1; i++)
    ns->fd[i] = -1;

  ns->fd_len = 0;
  ns->all_namespaces = 0;
  ns->namespaces_to_unshare = 0;
  ns->join_pidns = false;
  ns->join_ipcns = false;
  ns->must_fork = false;
  ns->delayed_userns_create = false;
  ns->userns_index = -1;
  ns->userns_index_origin = -1;
  ns->idx_pidns_to_join_immediately = -1;
  ns->idx_timens_to_join_immediately = -1;

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);

      ns->all_namespaces |= value;

      if (def->linux->namespaces[i]->path == NULL)
        ns->namespaces_to_unshare |= value;
      else
        {
          int fd;

          if (ns->fd_len >= MAX_NAMESPACES)
            return crun_make_error (err, 0, "too many namespaces to join");

          fd = open (def->linux->namespaces[i]->path, O_RDONLY | O_CLOEXEC);
          if (UNLIKELY (fd < 0))
            return crun_make_error (err, errno, "open `%s`", def->linux->namespaces[i]->path);

          if (value == CLONE_NEWUSER)
            {
              ns->userns_index = ns->fd_len;
              ns->userns_index_origin = i;
            }

          ns->fd[ns->fd_len] = fd;
          ns->index[ns->fd_len] = i;
          ns->value[ns->fd_len] = value;
          ns->fd_len++;
          ns->fd[ns->fd_len] = -1;
        }
    }

  if (container->host_uid && (ns->all_namespaces & CLONE_NEWUSER) == 0)
    {
      libcrun_warning ("non root user need to have an 'user' namespace");
      ns->all_namespaces |= CLONE_NEWUSER;
      ns->namespaces_to_unshare |= CLONE_NEWUSER;
    }

  return 0;
}

/* Detect if root is available in the container.  */
static bool
root_mapped_in_container_p (runtime_spec_schema_defs_id_mapping **mappings, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    if (mappings[i]->container_id == 0)
      return true;

  return false;
}

static struct libcrun_fd_map *
get_devices_fd_map (libcrun_container_t *container)
{
  struct libcrun_fd_map *dev_fds = get_private_data (container)->dev_fds;

  if (dev_fds == NULL)
    {
      runtime_spec_schema_config_schema *def = container->container_def;
      size_t len = def->linux ? def->linux->devices_len : 0;

      dev_fds = make_libcrun_fd_map (len);
      get_private_data (container)->dev_fds = dev_fds;
    }
  return dev_fds;
}

static struct libcrun_fd_map *
get_fd_map (libcrun_container_t *container)
{
  struct libcrun_fd_map *mount_fds = get_private_data (container)->mount_fds;

  if (mount_fds == NULL)
    {
      runtime_spec_schema_config_schema *def = container->container_def;
      mount_fds = make_libcrun_fd_map (def->mounts_len);
      get_private_data (container)->mount_fds = mount_fds;
    }
  return mount_fds;
}

static bool
is_bind_mount (runtime_spec_schema_defs_mount *mnt)
{
  size_t i;

  for (i = 0; i < mnt->options_len; i++)
    {
      if (strcmp (mnt->options[i], "bind") == 0)
        return true;
      if (strcmp (mnt->options[i], "rbind") == 0)
        return true;
    }
  return false;
}

static char *
get_idmapped_option (runtime_spec_schema_defs_mount *mnt)
{
  size_t i;

  for (i = 0; i < mnt->options_len; i++)
    if (has_prefix (mnt->options[i], "idmap"))
      return mnt->options[i];
  return NULL;
}

static int
maybe_get_idmapped_mount (runtime_spec_schema_config_schema *def, runtime_spec_schema_defs_mount *mnt, pid_t pid, int *out_fd, libcrun_error_t *err)
{
  cleanup_close int newfs_fd = -1;
  cleanup_pid pid_t created_pid = -1;
  struct mount_attr_s attr = {
    0,
  };
  const char *idmap_option = "";
  cleanup_close int fd = -1;
  const char *options;
  char proc_path[64];
  bool has_mappings;
  int ret;

  *out_fd = -1;

  has_mappings = mnt->uid_mappings_len > 0 || mnt->gid_mappings_len > 0 || (idmap_option = get_idmapped_option (mnt));
  if (! has_mappings)
    return 0;

  if ((mnt->uid_mappings == NULL) != (mnt->gid_mappings == NULL))
    return crun_make_error (err, 0, "invalid mappings specified for the mount on `%s`", mnt->destination);

  /* If there are options specified, create a new user namespace with the configured mappings.  */
  options = strchr (idmap_option, '=');
  if (options)
    {
      /* Skip the '=' itself.  */
      options++;
      if (options[0] == '\0')
        options = NULL;
    }

  ret = maybe_create_userns_for_idmapped_mount (def, mnt, options, &created_pid, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (created_pid > 0)
    pid = created_pid;

  sprintf (proc_path, "/proc/%d/ns/user", pid);
  fd = open (proc_path, O_RDONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open `%s`", proc_path);

  if (is_bind_mount (mnt))
    {
      newfs_fd = syscall_open_tree (-1, mnt->source,
                                    AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE);
      if (UNLIKELY (newfs_fd < 0))
        return crun_make_error (err, errno, "open `%s`", mnt->source);
    }
  else
    {
      cleanup_close int fsopen_fd = -1;

      fsopen_fd = syscall_fsopen (mnt->type, FSOPEN_CLOEXEC);
      if (UNLIKELY (fsopen_fd < 0))
        return crun_make_error (err, errno, "fsopen `%s`", mnt->type);

      ret = syscall_fsconfig (fsopen_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "fsconfig create `%s`", mnt->type);

      newfs_fd = syscall_fsmount (fsopen_fd, FSMOUNT_CLOEXEC, 0);
      if (UNLIKELY (newfs_fd < 0))
        return crun_make_error (err, errno, "fsmount `%s`", mnt->type);
    }

  attr.attr_set = MOUNT_ATTR_IDMAP;
  attr.userns_fd = fd;

  ret = syscall_mount_setattr (newfs_fd, "", AT_EMPTY_PATH, &attr);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mount_setattr `%s`", mnt->destination);

  *out_fd = get_and_reset (&newfs_fd);
  return 0;
}

static uid_t
get_id_in_user_namespace (uid_t id, bool is_uid, runtime_spec_schema_config_schema *def)
{
  runtime_spec_schema_defs_id_mapping **mappings;
  size_t len;
  size_t i;

  mappings = is_uid ? def->linux->uid_mappings : def->linux->gid_mappings;
  len = is_uid ? def->linux->uid_mappings_len : def->linux->gid_mappings_len;

  for (i = 0; i < len; i++)
    {
      if (mappings[i]->container_id <= id
          && id < mappings[i]->container_id + mappings[i]->size)
        return id - mappings[i]->container_id + mappings[i]->host_id;
    }

  return is_uid ? get_overflow_uid () : get_overflow_gid ();
}

static int
precreate_device (libcrun_container_t *container, int devs_dirfd, size_t i, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  runtime_spec_schema_defs_linux_device *device;
  uid_t uid = get_overflow_uid ();
  gid_t gid = get_overflow_gid ();
  char name[64];
  mode_t type;
  dev_t dev;
  int ret;

  snprintf (name, sizeof (name), "%zu", i);

  device = def->linux->devices[i];

  type = (device->type[0] == 'b') ? S_IFBLK : ((device->type[0] == 'p') ? S_IFIFO : S_IFCHR);
  dev = makedev (device->major, device->minor);

  ret = mknodat (devs_dirfd, name, device->file_mode | type, dev);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mknod `%s`", device->path);

  if (def->linux)
    {
      uid = get_id_in_user_namespace (device->uid, true, def);
      gid = get_id_in_user_namespace (device->gid, false, def);
    }

  ret = fchownat (devs_dirfd, name, uid, gid, 0); /* lgtm [cpp/toctou-race-condition] */
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chown `%s`", device->path);

  return get_bind_mount (devs_dirfd, name, false, false, err);
}

static int
send_mounts (int sync_socket_host, struct libcrun_fd_map *fds, size_t how_many, size_t total, libcrun_error_t *err)
{
  size_t i;
  int ret;

  ret = TEMP_FAILURE_RETRY (write (sync_socket_host, &how_many, sizeof (how_many)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to sync socket");

  for (i = 0; i < total; i++)
    {
      if (fds->fds[i] >= 0)
        {
          ret = send_fd_to_socket_with_payload (sync_socket_host, fds->fds[i], (char *) &i, sizeof (i), err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  return 0;
}

static int
prepare_and_send_mount_mounts (libcrun_container_t *container, pid_t pid, int sync_socket_host, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close_map struct libcrun_fd_map *mount_fds = NULL;
  bool has_userns = (get_private_data (container)->unshare_flags & CLONE_NEWUSER) ? true : false;
  size_t how_many = 0;
  size_t i;
  int ret;

  if (def->mounts_len == 0)
    return 0;

  mount_fds = make_libcrun_fd_map (def->mounts_len);

  for (i = 0; i < def->mounts_len; i++)
    {
      mount_fds->fds[i] = -1;

      ret = maybe_get_idmapped_mount (def, def->mounts[i], pid, &(mount_fds->fds[i]), err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (mount_fds->fds[i] < 0 && has_userns && is_bind_mount (def->mounts[i]))
        {
          mount_fds->fds[i] = get_bind_mount (-1, def->mounts[i]->source, false, false, err);
          if (UNLIKELY (mount_fds->fds[i] < 0))
            crun_error_release (err);
        }

      if (mount_fds->fds[i] >= 0)
        how_many++;
    }

  return send_mounts (sync_socket_host, mount_fds, how_many, def->mounts_len, err);
}

static int
prepare_and_send_dev_mounts (libcrun_container_t *container, int sync_socket_host, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close_map struct libcrun_fd_map *dev_fds = NULL;
  bool has_userns = (get_private_data (container)->unshare_flags & CLONE_NEWUSER) ? true : false;
  cleanup_close int current_mountns = -1;
  cleanup_free char *state_dir = NULL;
  cleanup_free char *devs_path = NULL;
  cleanup_close int devs_mountfd = -1;
  cleanup_close int targetfd = -1;
  const char *context_type = NULL;
  const char *label = NULL;
  size_t how_many = 0;
  size_t i;
  int ret;

  if (def->linux == NULL || def->linux->devices_len == 0)
    return 0;

  dev_fds = make_libcrun_fd_map (def->linux->devices_len);

  if (! has_userns || is_empty_string (container->context->id) || geteuid () > 0)
    return send_mounts (sync_socket_host, dev_fds, how_many, def->linux->devices_len, err);

  state_dir = libcrun_get_state_directory (container->context->state_root, container->context->id);
  if (state_dir == NULL)
    return send_mounts (sync_socket_host, dev_fds, how_many, def->linux->devices_len, err);

  ret = append_paths (&devs_path, err, state_dir, "devs", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = mkdir (devs_path, 0700);
  if (UNLIKELY (ret < 0) && errno != EEXIST)
    return crun_make_error (err, errno, "mkdir `%s`", devs_path);

  current_mountns = open ("/proc/self/ns/mnt", O_RDONLY);
  if (UNLIKELY (current_mountns < 0))
    return crun_make_error (err, errno, "open `/proc/self/ns/mnt`");

  ret = unshare (CLONE_NEWNS);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "unshare `CLONE_NEWNS`");

  ret = mount (NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, errno, "mount `MS_REC | MS_PRIVATE`");
      goto restore_mountns;
    }

  if (container->container_def->linux && container->container_def->linux->mount_label)
    {
      label = container->container_def->linux->mount_label;
      context_type = get_selinux_context_type (container);
    }

  devs_mountfd = fsopen_mount ("tmpfs", context_type, label);
  if (UNLIKELY (devs_mountfd < 0))
    {
      ret = crun_make_error (err, errno, "fsopen_mount `tmpfs`");
      goto restore_mountns;
    }

  targetfd = open (devs_path, O_DIRECTORY | O_CLOEXEC);
  if (targetfd < 0)
    {
      ret = crun_make_error (err, errno, "open `%s`", devs_path);
      goto restore_mountns;
    }

  ret = fs_move_mount_to (devs_mountfd, targetfd, NULL);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, errno, "fs_move_mount_to `%s`", devs_path);
      goto restore_mountns;
    }

  close_and_reset (&targetfd);

  targetfd = openat (devs_mountfd, ".", O_DIRECTORY | O_CLOEXEC);
  if (targetfd < 0)
    {
      ret = crun_make_error (err, errno, "open `%s`", devs_path);
      goto restore_mountns;
    }

  for (i = 0; i < def->linux->devices_len; i++)
    {
      ret = precreate_device (container, targetfd, i, err);
      if (UNLIKELY (ret < 0))
        {
          crun_error_release (err);
          continue;
        }

      dev_fds->fds[i] = ret;

      if (dev_fds->fds[i] >= 0)
        how_many++;
    }

  ret = send_mounts (sync_socket_host, dev_fds, how_many, def->linux->devices_len, err);
restore_mountns:
  {
    int setns_ret;

    setns_ret = setns (current_mountns, CLONE_NEWNS);
    if (UNLIKELY (setns_ret < 0 && ret >= 0))
      return crun_make_error (err, errno, "setns `CLONE_NEWNS`");
  }
  return ret;
}

static int
prepare_and_send_mounts (libcrun_container_t *container, pid_t pid, int sync_socket_host, libcrun_error_t *err)
{
  int ret;

  ret = expect_success_from_sync_socket (sync_socket_host, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = prepare_and_send_mount_mounts (container, pid, sync_socket_host, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = prepare_and_send_dev_mounts (container, sync_socket_host, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
receive_mounts (struct libcrun_fd_map *fds, int sync_socket_container, libcrun_error_t *err)
{
  size_t i, how_many = 0;
  int ret;

  if (fds->nfds == 0)
    return 0;

  ret = TEMP_FAILURE_RETRY (read (sync_socket_container, &how_many, sizeof (how_many)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from sync socket");

  for (i = 0; i < how_many; i++)
    {
      size_t index;

      ret = receive_fd_from_socket_with_payload (sync_socket_container, (char *) &index, sizeof (index), err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (index >= fds->nfds)
        return crun_make_error (err, 0, "invalid mount data received");

      if (fds->fds[index] >= 0)
        TEMP_FAILURE_RETRY (close (fds->fds[index]));

      fds->fds[index] = ret;
    }

  return 0;
}

static int
set_id_init (libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  uid_t uid = 0;
  gid_t gid = 0;
  int ret;

  if (def->process && def->process->user && def->linux)
    {
      /*
        If it is running in a user namespace and root is not mapped
        use the UID/GID specified for running the container.
      */
      bool root_mapped = false;

      if (def->linux->uid_mappings_len != 0)
        {
          root_mapped = root_mapped_in_container_p (def->linux->uid_mappings, def->linux->uid_mappings_len);
          if (! root_mapped)
            uid = def->process->user->uid;
        }

      if (def->linux->gid_mappings_len != 0)
        {
          root_mapped = root_mapped_in_container_p (def->linux->gid_mappings, def->linux->gid_mappings_len);
          if (! root_mapped)
            gid = def->process->user->gid;
        }
    }

  ret = setresuid (uid, uid, uid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setresuid to `%d`", uid);

  ret = setresgid (gid, gid, gid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setresgid to `%d`", gid);

  return 0;
}

static int
init_container (libcrun_container_t *container, int sync_socket_container, struct init_status_s *init_status,
                libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  struct libcrun_fd_map *mount_fds = get_fd_map (container);
  pid_t pid_container = 0;
  size_t i;
  int ret;

  if (init_status->idx_pidns_to_join_immediately >= 0 || init_status->idx_timens_to_join_immediately >= 0)
    {
      pid_t new_pid;

      if (init_status->idx_pidns_to_join_immediately >= 0)
        {
          ret = setns (init_status->fd[init_status->idx_pidns_to_join_immediately], CLONE_NEWPID);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "cannot setns to target pidns");

          close_and_reset (&init_status->fd[init_status->idx_pidns_to_join_immediately]);
        }

      if (init_status->idx_timens_to_join_immediately >= 0)
        {
          ret = setns (init_status->fd[init_status->idx_timens_to_join_immediately], CLONE_NEWTIME);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "cannot setns to target timens");

          close_and_reset (&init_status->fd[init_status->idx_timens_to_join_immediately]);
        }

      new_pid = fork ();
      if (UNLIKELY (new_pid < 0))
        return crun_make_error (err, errno, "fork");

      if (new_pid)
        {
          /* Report the new PID to the parent and exit immediately.  */
          ret = send_success_to_sync_socket (sync_socket_container, err);
          if (UNLIKELY (ret < 0))
            kill (new_pid, SIGKILL);

          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &new_pid, sizeof (new_pid)));
          if (UNLIKELY (ret < 0))
            kill (new_pid, SIGKILL);

          _exit (0);
        }

      /* In the new process.  Wait for the parent to receive the new PID.  */
      ret = expect_success_from_sync_socket (sync_socket_container, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_set_oom (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (init_status->fd_len > 0)
    {
      ret = join_namespaces (def, init_status->fd, init_status->fd_len, init_status->index, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* If the container needs to join an existing PID namespace, take a reference to it
     before creating a new user namespace, as we could lose the access to the existing
     namespace.

     This cannot be done in the parent process (by `prepare_and_send_mounts`), since it is
     necessary to first join the target namespaces and then create the mount.
  */
  if ((init_status->all_namespaces & CLONE_NEWUSER) && (init_status->join_pidns || init_status->join_ipcns))
    {
      for (i = 0; i < def->mounts_len; i++)
        {
          int fd = -1;
          /* If for any reason the mount cannot be opened, ignore errors and continue.
             An error will be generated later if it is not possible to join the namespace.
          */
          if (init_status->join_pidns && strcmp (def->mounts[i]->type, "proc") == 0)
            fd = fsopen_mount (def->mounts[i]->type, NULL, NULL);
          if (init_status->join_ipcns && strcmp (def->mounts[i]->type, "mqueue") == 0)
            fd = fsopen_mount (def->mounts[i]->type, NULL, NULL);

          if (fd >= 0)
            {
              if (mount_fds->fds[i] >= 0)
                TEMP_FAILURE_RETRY (close (mount_fds->fds[i]));
              mount_fds->fds[i] = fd;
            }
        }
    }

  if (init_status->all_namespaces & CLONE_NEWUSER)
    {
      if (init_status->delayed_userns_create)
        {
          ret = unshare (CLONE_NEWUSER);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "unshare (CLONE_NEWUSER)");

          init_status->namespaces_to_unshare &= ~CLONE_NEWUSER;

          ret = send_success_to_sync_socket (sync_socket_container, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (init_status->userns_index < 0)
        {
          ret = expect_success_from_sync_socket (sync_socket_container, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          /* If we need to join another user namespace, do it immediately before creating any other namespace. */
          ret = setns (init_status->fd[init_status->userns_index], CLONE_NEWUSER);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "cannot setns `%s`",
                                    def->linux->namespaces[init_status->userns_index_origin]->path);
        }

      ret = set_id_init (container, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = join_namespaces (def, init_status->fd, init_status->fd_len, init_status->index, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (init_status->namespaces_to_unshare & ~CLONE_NEWCGROUP)
    {
      /* New namespaces to create for the container.  */
      ret = unshare (init_status->namespaces_to_unshare & ~CLONE_NEWCGROUP);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "unshare");
    }

  if (def->linux->time_offsets)
    {
      const char *const timens_offsets_file = "/proc/self/timens_offsets";
      char fmt_buffer[128];
      cleanup_close int fd = -1;

      fd = open (timens_offsets_file, O_WRONLY | O_CLOEXEC);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open `%s`", timens_offsets_file);
      if (def->linux->time_offsets->boottime)
        {
          sprintf (fmt_buffer, "boottime %" PRIi64 " %" PRIu32, def->linux->time_offsets->boottime->secs, def->linux->time_offsets->boottime->nanosecs);
          ret = write (fd, fmt_buffer, strlen (fmt_buffer));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write `%s`", timens_offsets_file);
        }
      if (def->linux->time_offsets->monotonic)
        {
          sprintf (fmt_buffer, "monotonic %" PRIi64 " %" PRIu32, def->linux->time_offsets->monotonic->secs, def->linux->time_offsets->monotonic->nanosecs);
          ret = write (fd, fmt_buffer, strlen (fmt_buffer));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write `%s`", timens_offsets_file);
        }
    }

  ret = prctl (PR_SET_DUMPABLE, 0, 0, 0, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "prctl (PR_SET_DUMPABLE)");

  if (init_status->must_fork)
    {
      /* A PID and a time namespace are joined when the new process is created.  */
      pid_container = fork ();
      if (UNLIKELY (pid_container < 0))
        return crun_make_error (err, errno, "cannot fork");

      /* Report back the new PID.  */
      if (pid_container)
        {
          ret = send_success_to_sync_socket (sync_socket_container, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &pid_container, sizeof (pid_container)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write to sync socket");

          _exit (EXIT_SUCCESS);
        }

      ret = expect_success_from_sync_socket (sync_socket_container, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = send_success_to_sync_socket (sync_socket_container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Receive the mounts sent by `prepare_and_send_mounts`.  */
  ret = receive_mounts (get_fd_map (container), sync_socket_container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = receive_mounts (get_devices_fd_map (container), sync_socket_container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_container_setgroups (container, container->container_def->process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
handle_pidfd_receiver (pid_t pid, libcrun_container_t *container, libcrun_error_t *err)
{
  cleanup_close int client_fd = -1;
  cleanup_close int pidfd = -1;
  const char *v;

  v = find_annotation (container, "run.oci.pidfd_receiver");
  if (v == NULL)
    return 0;

  pidfd = syscall_pidfd_open (pid, 0);
  if (UNLIKELY (pidfd < 0))
    return crun_make_error (err, errno, "pidfd_open");

  client_fd = open_unix_domain_client_socket (v, 0, err);
  if (UNLIKELY (client_fd < 0))
    return client_fd;

  return send_fd_to_socket (client_fd, pidfd, err);
}

pid_t
libcrun_run_linux_container (libcrun_container_t *container, container_entrypoint_t entrypoint, void *args,
                             int *sync_socket_out, struct libcrun_dirfd_s *cgroup_dirfd, libcrun_error_t *err)
{
  __attribute__ ((cleanup (cleanup_free_init_statusp))) struct init_status_s init_status;
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close int sync_socket_container = -1;
  char *notify_socket_env = NULL;
  cleanup_close int sync_socket_host = -1;
  __attribute__ ((unused)) cleanup_close int restore_pidns = -1;
  int first_clone_args = 0;
  int sync_socket[2];
  pid_t pid;
  size_t i;
  int ret;

  ret = configure_init_status (&init_status, container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  get_private_data (container)->unshare_flags = init_status.all_namespaces;
#if CLONE_NEWCGROUP
  /* cgroup will be unshared later.  Once the process is in the correct cgroup.  */
  init_status.all_namespaces &= ~CLONE_NEWCGROUP;
  get_private_data (container)->unshare_cgroupns = init_status.namespaces_to_unshare & CLONE_NEWCGROUP;
#endif

  ret = socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sync_socket);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "socketpair");

  sync_socket_host = sync_socket[0];
  sync_socket_container = sync_socket[1];

#ifdef HAVE_SYSTEMD
  if (def->root)
    {
      ret = do_notify_socket (container, def->root->path, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
#endif

  get_uid_gid_from_def (container->container_def, &container->container_uid, &container->container_gid);

  /* This must be done before we enter a user namespace.  */
  if (def->process)
    {
      ret = libcrun_set_rlimits (def->process->rlimits, def->process->rlimits_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_set_oom (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* If a new user namespace must be created, but there are other namespaces to join, then delay
     the userns creation after the namespaces are joined.  */
  init_status.delayed_userns_create
      = (init_status.all_namespaces & CLONE_NEWUSER) && init_status.userns_index < 0 && init_status.fd_len > 0;

  /* Check if special handling is required to join the namespaces.  */
  for (i = 0; i < init_status.fd_len; i++)
    {
      switch (init_status.value[i])
        {
        case CLONE_NEWIPC:
          if (init_status.all_namespaces & CLONE_NEWUSER)
            init_status.join_ipcns = true;
          break;

        case CLONE_NEWPID:
          if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
            init_status.must_fork = true;
          else
            {
              init_status.join_pidns = true;
              init_status.idx_pidns_to_join_immediately = i;
              init_status.namespaces_to_unshare &= ~CLONE_NEWPID;
            }
          break;

        case CLONE_NEWTIME:
          if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
            init_status.must_fork = true;
          else
            {
              init_status.idx_timens_to_join_immediately = i;
              init_status.namespaces_to_unshare &= ~CLONE_NEWTIME;
            }
          break;
        }
    }

  /* Before attempting any setns() or unshare(), a clone() is required to not touch the caller context
     that can be used later on for running hooks.  */

  if ((init_status.namespaces_to_unshare & CLONE_NEWUSER) && init_status.fd_len == 0)
    {
      /* If a user namespace must be created and there are no other namespaces to join, create the userns alone.  */
      first_clone_args = CLONE_NEWUSER;
    }
  else if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
    {
      /* If it doesn't create a user namespace or need to join one, create the new requested namespaces now. */
      first_clone_args = init_status.namespaces_to_unshare & ~(CLONE_NEWTIME | CLONE_NEWCGROUP);
    }

  init_status.namespaces_to_unshare &= ~first_clone_args;

  /* Check if there are still namespaces that require a fork().  */
  if (init_status.namespaces_to_unshare & (CLONE_NEWPID | CLONE_NEWTIME))
    {
      /* If we need to make another fork(), make sure the NEWPID is always
         created as part of that.  */
      first_clone_args &= ~CLONE_NEWPID;
      init_status.namespaces_to_unshare |= CLONE_NEWPID;
      init_status.must_fork = true;
    }

  pid = -1;
  if (cgroup_dirfd && *cgroup_dirfd->dirfd >= 0)
    {
      struct _clone3_args clone3_args;
      memset (&clone3_args, 0, sizeof (clone3_args));
      clone3_args.exit_signal = SIGCHLD;
      clone3_args.flags = first_clone_args;

      clone3_args.flags |= CLONE_INTO_CGROUP;
      clone3_args.cgroup = *cgroup_dirfd->dirfd;

      pid = syscall_clone3 (&clone3_args);
      if (pid >= 0)
        cgroup_dirfd->joined = true;

      close_and_reset (cgroup_dirfd->dirfd);
    }
  /* fallback to clone() for any error.  */
  if (pid < 0)
    {
      pid = syscall_clone (first_clone_args | SIGCHLD, NULL);
      if (UNLIKELY (pid < 0))
        return crun_make_error (err, errno, "clone");
    }

  if (pid)
    {
      __attribute__ ((unused)) cleanup_pid pid_t pid_to_clean = pid;

      /* this is safe to do because the std stream files were not changed since the clone().  */
      ret = libcrun_save_external_descriptors (container, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = close_and_reset (&sync_socket_container);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "close");

      /* any systemd notify socket open_tree FD is pointless to keep around in the parent */
      close_and_reset (&(get_private_data (container)->notify_socket_tree_fd));

      if (init_status.idx_pidns_to_join_immediately >= 0 || init_status.idx_timens_to_join_immediately >= 0)
        {
          pid_t new_pid = 0;

          ret = expect_success_from_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (read (sync_socket_host, &new_pid, sizeof (new_pid)));
          if (UNLIKELY (ret != sizeof (new_pid)))
            return crun_make_error (err, errno, "read pid from sync socket");

          /* Cleanup the first process.  */
          ret = waitpid_ignore_stopped (pid, NULL, 0);

          pid_to_clean = pid = new_pid;

          ret = send_success_to_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (init_status.delayed_userns_create)
        {
          ret = expect_success_from_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if ((init_status.all_namespaces & CLONE_NEWUSER) && init_status.userns_index < 0)
        {
          ret = libcrun_set_usernamespace (container, pid, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = send_success_to_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (init_status.must_fork)
        {
          pid_t grandchild = 0;

          ret = expect_success_from_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (read (sync_socket_host, &grandchild, sizeof (grandchild)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read pid from sync socket");

          ret = send_success_to_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;

          /* Cleanup the first process.  */
          waitpid_ignore_stopped (pid, NULL, 0);

          pid_to_clean = pid = grandchild;
        }

      /* They are received by `receive_mounts`.  */
      ret = prepare_and_send_mounts (container, pid, sync_socket_host, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = expect_success_from_sync_socket (sync_socket_host, err);
      if (UNLIKELY (ret < 0))
        return ret;

      *sync_socket_out = get_and_reset (&sync_socket_host);

      ret = handle_pidfd_receiver (pid, container, err);
      if (UNLIKELY (ret < 0))
        return ret;

      pid_to_clean = 0;
      return pid;
    }

  /* Inside the container process.  */

  ret = close_and_reset (&sync_socket_host);
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "%s", "close sync socket");

  /* Initialize the new process and make sure to join/create all the required namespaces.  */
  ret = init_container (container, sync_socket_container, &init_status, err);
  if (UNLIKELY (ret < 0))
    send_error_to_sync_socket_and_die (sync_socket_container, false, err);
  else
    {
      ret = send_success_to_sync_socket (sync_socket_container, err);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error (crun_error_get_errno (err), "%s", (*err)->msg);
    }

  /* Jump into the specified entrypoint.  */
  if (container->context->notify_socket)
    xasprintf (&notify_socket_env, "NOTIFY_SOCKET=%s/notify", container->context->notify_socket);

  ret = entrypoint (args, notify_socket_env, sync_socket_container, err);

  /* For most of the cases ENTRYPOINT returns only on an error, fallback here */
  /* Except for custom handlers which could perform a task and return with success */
  /* since custom handlers could or could not be {long-running, blocking} */
  if (*err)
    libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

  /* If cursor is here most likely we returned from a custom handler eg. wasm, libkrun */
  /* Allow cleanup attributes to perform cleanup and exit with success if return code was 0 */
  if (ret == 0)
    _exit (EXIT_SUCCESS);

  _exit (EXIT_FAILURE);
}

static int
join_process_parent_helper (runtime_spec_schema_config_schema_process *process,
                            pid_t child_pid, int sync_socket_fd,
                            libcrun_container_status_t *status,
                            bool need_move_to_cgroup, const char *sub_cgroup,
                            int *terminal_fd, libcrun_error_t *err)
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
  ret = waitpid_ignore_stopped (child_pid, &pid_status, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "waitpid for exec child pid");

  if (need_move_to_cgroup)
    {
      if (sub_cgroup)
        {
          cleanup_free char *final_cgroup = NULL;

          ret = append_paths (&final_cgroup, err, status->cgroup_path, sub_cgroup, NULL);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = libcrun_move_process_to_cgroup (pid, status->pid, final_cgroup, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = libcrun_move_process_to_cgroup (pid, status->pid, status->cgroup_path, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      /* Join the scheduler immediately after joining the cgroup.  */
      ret = libcrun_set_scheduler (pid, process, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_set_io_priority (pid, process, err);
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
        {
          int err_code = 0;
          cleanup_free char *err_str = NULL;

          if (read_error_from_sync_socket (sync_fd, &err_code, &err_str))
            return crun_make_error (err, err_code, "%s", err_str);

          return crun_error_wrap (err, "receive fd");
        }
      *terminal_fd = ret;
    }

  return pid;
}

/*
  try to join all the namespaces with a single call to setns using the target process pidfd.

  return codes:
  < 0 - on errors
  0   - the namespaces were not joined.
  > 0 - the namespaces were joined.
*/
static int
try_setns_with_pidfd (pid_t pid_to_join, libcrun_container_t *container, libcrun_container_status_t *status, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close int pidfd_pid_to_join = -1;
  int all_flags = 0;
  size_t i;
  int ret;

  /* If there is any explicit namespace path to join, skip the setns_with_pidfd
     shortcut and join each namespace individually.  */
  if (def->linux && def->linux->namespaces)
    {
      for (i = 0; i < def->linux->namespaces_len; i++)
        if (! is_empty_string (def->linux->namespaces[i]->path))
          return 0;
    }

  pidfd_pid_to_join = syscall_pidfd_open (pid_to_join, 0);
  if (UNLIKELY (pidfd_pid_to_join < 0))
    return 0;

  /* Validate that the pidfd really refers to the original container process.  */
  ret = libcrun_check_pid_valid (status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret == 0)
    return crun_make_error (err, ESRCH, "container process not found, the pid was reused");

  for (i = 0; namespaces[i].ns_file; i++)
    all_flags |= namespaces[i].value;

  ret = setns (pidfd_pid_to_join, all_flags);
  if (UNLIKELY (ret < 0))
    return 0;

  return 1;
}

static int
join_process_namespaces (libcrun_container_t *container, pid_t pid_to_join, libcrun_container_status_t *status, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int fds_joined[MAX_NAMESPACES] = {
    0,
  };
  int fds[MAX_NAMESPACES] = {
    -1,
  };
  size_t i;
  int ret;

  /* Try to join all namespaces in one shot with setns and pidfd.  */
  ret = try_setns_with_pidfd (pid_to_join, container, status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  /* Nothing left to do if the namespaces were joined.  */
  if (LIKELY (ret > 0))
    return 0;

  /* If setns fails with the target pidfd, fall-back to join each namespace individually.  */

  if (def->linux->namespaces_len >= MAX_NAMESPACES)
    return crun_make_error (err, 0, "invalid configuration");

  for (i = 0; namespaces[i].ns_file; i++)
    {
      cleanup_free char *ns_join = NULL;

      xasprintf (&ns_join, "/proc/%d/ns/%s", pid_to_join, namespaces[i].ns_file);
      fds[i] = open (ns_join, O_RDONLY);
      if (UNLIKELY (fds[i] < 0))
        {
          /* If the namespace doesn't exist, just ignore it.  */
          if (errno == ENOENT)
            continue;

          ret = crun_make_error (err, errno, "open `%s`", ns_join);
          goto exit;
        }
    }

  for (i = 0; namespaces[i].ns_file; i++)
    {
      if (namespaces[i].value == CLONE_NEWUSER)
        continue;

      ret = setns (fds[i], 0);
      if (ret == 0)
        fds_joined[i] = 1;
    }
  for (i = 0; namespaces[i].ns_file; i++)
    {
      ret = setns (fds[i], 0);
      if (ret == 0)
        fds_joined[i] = 1;
    }
  for (i = 0; namespaces[i].ns_file; i++)
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
              if (strcmp (namespaces[i].name, def->linux->namespaces[j]->type) == 0)
                {
                  found = true;
                  break;
                }
            }
          if (! found)
            {
              /* It was not requested to create this ns, so just ignore it.  */
              fds_joined[i] = 1;
              continue;
            }

          ret = crun_make_error (err, errno, "setns `%s`", namespaces[i].ns_file);
          goto exit;
        }
      fds_joined[i] = 1;
    }

  ret = 0;

exit:
  for (i = 0; namespaces[i].ns_file; i++)
    close_and_reset (&fds[i]);

  return ret;
}

int
libcrun_join_process (libcrun_container_t *container, pid_t pid_to_join,
                      libcrun_container_status_t *status, const char *sub_cgroup,
                      int detach, runtime_spec_schema_config_schema_process *process,
                      int *terminal_fd, libcrun_error_t *err)
{
  pid_t pid;
  int ret;
  int sync_socket_fd[2];
  cleanup_close int cgroup_dirfd = -1;
  cleanup_close int sync_fd = -1;
  struct _clone3_args clone3_args;
  bool need_move_to_cgroup;

  if (! detach)
    {
      ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "set child subreaper");
    }

  ret = socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sync_socket_fd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error creating socketpair");

  {
    cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;

    cgroup_status = libcrun_cgroup_make_status (status);

    /* The cgroup can be joined directly only when there are no additional
       controllers not handled by cgroup v2.  */
    if (get_force_cgroup_v1_annotation (container) == NULL)
      {
        cgroup_dirfd = libcrun_get_cgroup_dirfd (cgroup_status, sub_cgroup, err);
        if (UNLIKELY (cgroup_dirfd < 0))
          crun_error_release (err);
      }
  }

  memset (&clone3_args, 0, sizeof (clone3_args));
  clone3_args.exit_signal = SIGCHLD;
  if (cgroup_dirfd < 0)
    need_move_to_cgroup = true;
  else
    {
      need_move_to_cgroup = false;
      clone3_args.flags |= CLONE_INTO_CGROUP;
      clone3_args.cgroup = cgroup_dirfd;
    }

  pid = syscall_clone3 (&clone3_args);

  if (pid > 0)
    {
      /* We need to set the scheduler as soon as possible after joining the cgroup,
         because if it is a RT scheduler, other processes in the container could already
         take the entire cpu time and stall the new process.  */
      ret = libcrun_set_scheduler (pid, process, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* On errors, fall back to fork().  */
  if (pid < 0)
    {
      need_move_to_cgroup = true;

      pid = fork ();
      if (UNLIKELY (pid < 0))
        {
          ret = crun_make_error (err, errno, "fork");
          goto exit;
        }
    }

  if (pid)
    {
      close_and_reset (&sync_socket_fd[1]);
      sync_fd = sync_socket_fd[0];
      return join_process_parent_helper (process,
                                         pid, sync_fd, status,
                                         need_move_to_cgroup,
                                         sub_cgroup,
                                         terminal_fd, err);
    }

  close_and_reset (&sync_socket_fd[0]);
  sync_fd = sync_socket_fd[1];

  ret = join_process_namespaces (container, pid_to_join, status, err);
  if (UNLIKELY (ret < 0))
    {
      TEMP_FAILURE_RETRY (write (sync_fd, "1", 1));
      libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
    }

  if (setsid () < 0)
    {
      int saved_errno = errno;
      TEMP_FAILURE_RETRY (write (sync_fd, "1", 1));
      libcrun_fail_with_error (saved_errno, "setsid");
    }

  /* We need to fork once again to join the PID namespace.  */
  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      int saved_errno = errno;
      TEMP_FAILURE_RETRY (write (sync_fd, "1", 1));
      libcrun_fail_with_error (saved_errno, "setsid");
    }

  if (pid)
    {
      /* Just return the PID to the parent helper and exit.  */
      ret = TEMP_FAILURE_RETRY (write (sync_fd, "0", 1));
      if (UNLIKELY (ret < 0))
        {
          kill (pid, SIGKILL);
          _exit (EXIT_FAILURE);
        }

      ret = TEMP_FAILURE_RETRY (write (sync_fd, &pid, sizeof (pid)));
      if (UNLIKELY (ret < 0))
        {
          kill (pid, SIGKILL);
          _exit (EXIT_FAILURE);
        }

      _exit (EXIT_SUCCESS);
    }
  else
    {
      /* Inside the grandchild process.  The real process
         used for the container.  */
      cleanup_free char *pty = NULL;
      int r = -1;

      ret = TEMP_FAILURE_RETRY (read (sync_fd, &r, sizeof (r)));
      if (UNLIKELY (ret < 0))
        _exit (EXIT_FAILURE);

      if (terminal_fd)
        {
          cleanup_close int ptmx_fd = -1;

          ret = setsid ();
          if (ret < 0)
            {
              crun_make_error (err, errno, "setsid");
              send_error_to_sync_socket_and_die (sync_fd, true, err);
            }

          ret = set_id_init (container, err);
          if (UNLIKELY (ret < 0))
            send_error_to_sync_socket_and_die (sync_fd, true, err);

          ptmx_fd = open_terminal (&pty, process, err);
          if (UNLIKELY (ptmx_fd < 0))
            send_error_to_sync_socket_and_die (sync_fd, true, err);

          ret = send_fd_to_socket (sync_fd, ptmx_fd, err);
          if (UNLIKELY (ret < 0))
            send_error_to_sync_socket_and_die (sync_fd, true, err);
        }

      if (r < 0)
        _exit (EXIT_FAILURE);
    }

  return 0;

exit:
  if (sync_socket_fd[0] >= 0)
    TEMP_FAILURE_RETRY (close (sync_socket_fd[0]));
  if (sync_socket_fd[1] >= 0)
    TEMP_FAILURE_RETRY (close (sync_socket_fd[1]));
  return ret;
}

int
libcrun_linux_container_update (libcrun_container_status_t *status, runtime_spec_schema_config_linux_resources *resources, libcrun_error_t *err)
{
  cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;

  cgroup_status = libcrun_cgroup_make_status (status);

  return libcrun_update_cgroup_resources (cgroup_status, resources, err);
}

static int
libcrun_container_pause_unpause_linux (libcrun_container_status_t *status, const bool pause, libcrun_error_t *err)
{
  cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;

  cgroup_status = libcrun_cgroup_make_status (status);

  return libcrun_cgroup_pause_unpause (cgroup_status, pause, err);
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
libcrun_set_personality (runtime_spec_schema_defs_linux_personality *p, libcrun_error_t *err)
{
  unsigned long persona = 0;
  int ret;

  if (strcmp (p->domain, "LINUX") == 0)
    persona = PER_LINUX;
  else if (strcmp (p->domain, "LINUX32") == 0)
    persona = PER_LINUX32;
  else
    return crun_make_error (err, 0, "unknown persona specified `%s`", p->domain);

  ret = personality (persona);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "set personality to `%s`", p->domain);

  return 0;
}

int
libcrun_configure_network (libcrun_container_t *container, libcrun_error_t *err)
{
  int ret;
  size_t i;
  bool configure_network = false;
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close int sockfd = -1;

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);

      if (value == CLONE_NEWNET && def->linux->namespaces[i]->path == NULL)
        {
          configure_network = true;
          break;
        }
    }

  if (! configure_network)
    return 0;

  sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  if (LIKELY (sockfd >= 0))
    {
      struct ifreq ifr_lo = { .ifr_name = "lo", .ifr_flags = IFF_UP | IFF_RUNNING };

      ret = ioctl (sockfd, SIOCSIFFLAGS, &ifr_lo);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "ioctl(SIOCSIFFLAGS)");
    }
  else
    {
      struct nlmsghdr *hdr_recv;
      char buf[sizeof (struct nlmsghdr) + sizeof (struct ifinfomsg)];
      struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid (),
      };
      struct sockaddr_nl addr_to = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
      };
      struct nlmsghdr hdr = {
        .nlmsg_len = sizeof (struct nlmsghdr) + sizeof (struct ifinfomsg),
        .nlmsg_type = RTM_NEWLINK,
        .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        .nlmsg_seq = 1,
        .nlmsg_pid = 0,
      };
      struct ifinfomsg msg = {
        .ifi_family = AF_UNSPEC,
        .ifi_type = 0,
        .ifi_index = 1,
        .ifi_flags = IFF_UP,
        .ifi_change = IFF_UP,
      };

      *((struct nlmsghdr *) buf) = hdr;
      *((struct ifinfomsg *) (buf + sizeof (struct nlmsghdr))) = msg;

      sockfd = socket (PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
      if (UNLIKELY (sockfd < 0))
        return crun_make_error (err, errno, "socket(PF_NETLINK)");

      ret = bind (sockfd, (struct sockaddr *) &addr, sizeof (addr));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "bind(PF_NETLINK)");

      ret = sendto (sockfd, buf, sizeof (buf), 0, (struct sockaddr *) &addr_to, sizeof (addr_to));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "sendto(PF_NETLINK)");

      ret = recvfrom (sockfd, buf, sizeof (buf), 0, NULL, NULL);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "recvfrom(PF_NETLINK)");

      hdr_recv = (struct nlmsghdr *) buf;

      if (hdr_recv->nlmsg_type == NLMSG_ERROR)
        {
          /* The first 4 bytes in the data are the negative error code
             in native endianness.  */
          errno = -(*(int32_t *) (buf + sizeof (struct nlmsghdr)));
          if (UNLIKELY (errno < 0))
            return crun_make_error (err, errno, "recvfrom(PF_NETLINK)");
        }
    }

  return 0;
}

/* Protection for attacks like CVE-2019-5736.  */
int ensure_cloned_binary ();
__attribute__ ((constructor)) static void
libcrun_rexec (void)
{
  if (ensure_cloned_binary () < 0)
    {
      fprintf (stderr, "Failed to re-execute libcrun via memory file descriptor\n");
      _exit (EXIT_FAILURE);
    }
}

int
libcrun_container_checkpoint_linux (libcrun_container_status_t *status, libcrun_container_t *container,
                                    libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err)
{
  return libcrun_container_checkpoint_linux_criu (status, container, cr_options, err);
}

int
libcrun_container_restore_linux (libcrun_container_status_t *status, libcrun_container_t *container,
                                 libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err)
{
  int ret;
  ret = libcrun_container_restore_linux_criu (status, container, cr_options, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

/* Fallback to use kill(2) on systems where pidfd is not available.  */
static int
libcrun_kill_linux_no_pidfd (libcrun_container_status_t *status, bool check_pid, int signal, libcrun_error_t *err)
{
  int ret;

  /* There is still a possibility that the pid is killed between the check
     and the time we send the signal, but attempt to reduce the window of time when
     it is possible.  */
  if (check_pid)
    {
      ret = libcrun_check_pid_valid (status, err);
      if (UNLIKELY (ret < 0))
        return ret;

      /* The pid is not valid anymore, return an error.  */
      if (ret == 0)
        {
          errno = ESRCH;
          return crun_make_error (err, errno, "kill container");
        }
    }

  ret = kill (status->pid, signal);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "kill container");
  return 0;
}

int
libcrun_kill_linux (libcrun_container_status_t *status, int signal, libcrun_error_t *err)
{
  int ret;
  cleanup_close int pidfd = -1;

  pidfd = syscall_pidfd_open (status->pid, 0);
  if (UNLIKELY (pidfd < 0))
    {
      /* If pidfd_open is not supported, fallback to kill.  */
      if (errno == ENOSYS)
        return libcrun_kill_linux_no_pidfd (status, true, signal, err);

      return crun_make_error (err, errno, "open pidfd");
    }

  ret = libcrun_check_pid_valid (status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* The pid is not valid anymore, return an error.  */
  if (ret == 0)
    {
      errno = ESRCH;
      return crun_make_error (err, errno, "kill container");
    }

  ret = syscall_pidfd_send_signal (pidfd, signal, NULL, 0);
  if (UNLIKELY (ret < 0))
    {
      /* If pidfd_send_signal is not supported, fallback to kill.  */
      if (errno == ENOSYS)
        return libcrun_kill_linux_no_pidfd (status, false, signal, err);
      return crun_make_error (err, errno, "send signal to pidfd");
    }

  return 0;
}
