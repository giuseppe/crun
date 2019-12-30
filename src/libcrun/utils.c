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
#include "utils.h"
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <limits.h>

int
close_and_reset (int *fd)
{
  int ret = 0;
  if (*fd >= 0)
    {
      ret = TEMP_FAILURE_RETRY (close (*fd));
      if (LIKELY (ret == 0))
        *fd = -1;
    }
  return ret;
}

void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

void
cleanup_closep (void *p)
{
  int *pp = p;
  if (*pp >= 0)
    TEMP_FAILURE_RETRY (close (*pp));
}

void
cleanup_close_vecp (int **p)
{
  int *pp = *p;
  int i;

  for (i = 0; pp[i] >= 0; i++)
    TEMP_FAILURE_RETRY (close (pp[i]));
}

void
cleanup_dirp (DIR **p)
{
  DIR *dir = *p;
  if (dir)
    closedir (dir);
}

void *
xmalloc (size_t size)
{
  void *res = malloc (size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

char *
argp_mandatory_argument (char *arg, struct argp_state *state)
{
  if (arg)
    return arg;
  return state->argv[state->next++];
}

int
crun_path_exists (const char *path, libcrun_error_t *err arg_unused)
{
  int ret = access (path, F_OK);
  if (ret < 0)
    return 0;
  return 1;
}

int
xasprintf (char **str, const char *fmt, ...)
{
  int ret;
  va_list args_list;

  va_start (args_list, fmt);

  ret = vasprintf (str, fmt, args_list);
  if (UNLIKELY (ret < 0))
    OOM ();

  va_end (args_list);
  return ret;
}

char *
xstrdup (const char *str)
{
  char *ret;
  if (str == NULL)
    return NULL;

  ret = strdup (str);
  if (ret == NULL)
    OOM ();

  return ret;
}

int
write_file_at (int dirfd, const char *name, const void *data, size_t len, libcrun_error_t *err)
{
  cleanup_close int fd = openat (dirfd, name, O_WRONLY | O_CREAT, 0700);
  int ret = 0;
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  if (len)
    {
      ret = TEMP_FAILURE_RETRY (write (fd, data, len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "writing file '%s'", name);
    }

  return ret;
}

int
write_file (const char *name, const void *data, size_t len, libcrun_error_t *err)
{
  cleanup_close int fd = open (name, O_WRONLY | O_CREAT, 0700);
  int ret;
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  ret = TEMP_FAILURE_RETRY (write (fd, data, len));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  return ret;
}

int
detach_process ()
{
  pid_t pid;
  if (setsid () < 0)
    return -1;
  pid = fork ();
  if (pid < 0)
    return -1;
  if (pid != 0)
    _exit (EXIT_SUCCESS);
  return 0;
}

int
get_file_type_at (int dirfd, mode_t *mode, bool nofollow, const char *path)
{
  struct stat st;
  int ret;

#ifdef HAVE_STATX
  struct statx stx;

  ret = statx (dirfd, path, (nofollow ? AT_SYMLINK_NOFOLLOW : 0) | AT_STATX_DONT_SYNC, STATX_TYPE, &stx);
  if (UNLIKELY (ret < 0))
    {
      if (errno == ENOSYS || errno == EINVAL)
        goto fallback;

      return ret;
    }
  *mode = stx.stx_mode;
  return ret;

 fallback:
#endif
  ret = fstatat (dirfd, path, &st, nofollow ? AT_SYMLINK_NOFOLLOW : 0);
  *mode = st.st_mode;
  return ret;
}

int
get_file_type (mode_t *mode, bool nofollow, const char *path)
{
  return get_file_type_at (AT_FDCWD, mode, nofollow, path);
}

int
create_file_if_missing_at (int dirfd, const char *file, libcrun_error_t *err)
{
  cleanup_close int fd_write = openat (dirfd, file, O_CREAT | O_WRONLY, 0700);
  if (fd_write < 0)
    {
      mode_t mode;
      int ret;

      /* On errors, check if the file already exists.  */
      ret = get_file_type_at (dirfd, &mode, false, file);
      if (ret == 0 && S_ISREG (mode))
        return 0;

      return crun_make_error (err, errno, "creating file '%s'", file);
    }
  return 0;
}

int
create_file_if_missing (const char *file, libcrun_error_t *err)
{
  cleanup_close int fd_write = open (file, O_CREAT | O_WRONLY, 0700);
  if (fd_write < 0)
    {
      mode_t mode;
      int ret;

      /* On errors, check if the file already exists.  */
      ret = get_file_type (&mode, false, file);
      if (ret == 0 && S_ISREG (mode))
        return 0;

      return crun_make_error (err, errno, "creating file '%s'", file);
    }
  return 0;
}

static int
ensure_directory_internal_at (int dirfd, char *path, size_t len, int mode, libcrun_error_t *err)
{
  char *it = path + len;
  int ret = 0;
  int parent_created;

  for (parent_created = 0; parent_created < 2; parent_created++)
    {
      ret = mkdirat (dirfd, path, mode);
      if (ret == 0)
        break;

      if (errno == EEXIST)
        {
          ret = 0;
          break;
        }

      if (errno != ENOENT || parent_created)
        {
          /* On errors check if the directory already exists.  */
          ret = crun_dir_p (path, false, err);
          if (ret > 0)
            break;

          return crun_make_error (err, errno, "creating file '%s'", path);
        }
      else
        {
          while (it > path && *it != '/')
            {
              it--;
              len--;
            }
          if (it == path)
            {
              ret = 0;
              break;
            }

          *it = '\0';
          ret = ensure_directory_internal_at (dirfd, path, len - 1, mode, err);
          *it = '/';
          if (UNLIKELY (ret < 0))
            break;
        }
    }
  return ret;
}

int
crun_ensure_directory_at (int dirfd, const char *path, int mode, bool nofollow, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *tmp = xstrdup (path);
  ret = ensure_directory_internal_at (dirfd, tmp, strlen (tmp), mode, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = crun_dir_p_at (dirfd, path, nofollow, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (ret == 0)
    return crun_make_error (err, ENOTDIR, "The path '%s' is not a directory", path);

  return 0;
}

int
crun_ensure_directory (const char *path, int mode, bool nofollow, libcrun_error_t *err)
{
  return crun_ensure_directory_at (AT_FDCWD, path, mode, nofollow, err);
}

int
crun_ensure_file_at (int dirfd, const char *path, int mode, bool nofollow, libcrun_error_t *err)
{
  cleanup_free char *tmp = xstrdup (path);
  size_t len = strlen (tmp);
  char *it = tmp + len - 1;
  int ret;

  while (*it != '/' && it > tmp)
    it--;
  if (it > tmp)
    {
      *it = '\0';
      ret = crun_ensure_directory_at (dirfd, tmp, mode, nofollow, err);
      if (UNLIKELY (ret < 0))
        return ret;
      *it = '/';

      return create_file_if_missing_at (dirfd, tmp, err);
    }
  return 0;
}

int
crun_ensure_file (const char *path, int mode, bool nofollow, libcrun_error_t *err)
{
  return crun_ensure_file_at (AT_FDCWD, path, mode, nofollow, err);
}

static int
get_file_size (int fd, off_t *size)
{
  struct stat st;
  int ret;
#ifdef HAVE_STATX
  struct statx stx;

  ret = statx (fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_STATX_DONT_SYNC, STATX_SIZE, &stx);
  if (UNLIKELY (ret < 0))
    {
      if (errno == ENOSYS || errno == EINVAL)
        goto fallback;
      return ret;
    }
  *size = stx.stx_size;

  return ret;

 fallback:
#endif
  ret = fstat (fd, &st);
  *size = st.st_size;
  return ret;
}

int
crun_dir_p_at (int dirfd, const char *path, bool nofollow, libcrun_error_t *err)
{
  mode_t mode;
  int ret;

  ret = get_file_type_at (dirfd, &mode, nofollow, path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error stat'ing file '%s'", path);

  return S_ISDIR (mode);
}

int
crun_dir_p (const char *path, bool nofollow, libcrun_error_t *err)
{
  return crun_dir_p_at (AT_FDCWD, path, nofollow, err);
}

int
check_running_in_user_namespace (libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  size_t len;
  int ret = read_all_file ("/proc/self/uid_map", &buffer, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return strstr (buffer, "4294967295") ? 0 : 1;
}

static int selinux_enabled = -1;
static int apparmor_enabled = -1;

int
libcrun_initialize_selinux (libcrun_error_t *err)
{
  cleanup_free char *out = NULL;
  cleanup_close int fd = -1;
  size_t len;
  int ret;

  if (selinux_enabled >= 0)
    return selinux_enabled;

  fd = open ("/proc/mounts", O_RDONLY | O_CLOEXEC);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open /proc/mounts");

  ret = read_all_fd (fd, "/proc/mounts", &out, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  selinux_enabled = strstr (out, "selinux") ? 1 : 0;

  return selinux_enabled;
}

int
libcrun_initialize_apparmor (libcrun_error_t *err arg_unused)
{
  cleanup_close int fd = -1;
  int size;
  char buf[2];

  if (apparmor_enabled >= 0)
    return apparmor_enabled;

  fd = open ("/sys/module/apparmor/parameters/enabled", O_RDONLY | O_CLOEXEC);
  if (fd == -1)
    return 0;

  size = TEMP_FAILURE_RETRY (read (fd, &buf, 2));

  apparmor_enabled = size > 0 && buf[0] == 'Y' ? 1 : 0;

  return apparmor_enabled;
}

static int
libcrun_is_selinux_enabled (libcrun_error_t *err)
{
  if (selinux_enabled < 0)
    return crun_make_error (err, 0, "SELinux not initialized correctly");
  return selinux_enabled;
}

int
add_selinux_mount_label (char **retlabel, const char *data, const char *label, libcrun_error_t *err arg_unused)
{
  int ret;

  ret = libcrun_is_selinux_enabled (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (label && ret)
    {
      if (data && *data)
        xasprintf (retlabel, "%s,context=\"%s\"", data, label);
      else
        xasprintf (retlabel, "context=\"%s\"", label);
      return 0;
    }
  *retlabel = xstrdup (data);
  return 0;

}

static int
write_file_and_check_fs_type (const char *file, const char *data, size_t len, unsigned int type, const char *type_name, libcrun_error_t *err)
{
  int ret;
  struct statfs sfs;
  cleanup_close int fd = -1;

  fd = open (file, O_WRONLY | O_CLOEXEC);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open file '%s'", file);

  ret = fstatfs (fd, &sfs);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "statfs '%s'", file);

  if (sfs.f_type != type)
    return crun_make_error (err, 0, "the file '%s' is not on file system type '%s'", file, type_name);

  ret = TEMP_FAILURE_RETRY (write (fd, data, len));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write file '%s'", file);

  return 0;
}

int
set_selinux_exec_label (const char *label, libcrun_error_t *err)
{
  int ret;

  ret = libcrun_is_selinux_enabled (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (ret)
    {
      ret = write_file_and_check_fs_type ("/proc/thread-self/attr/exec", label, strlen (label), PROC_SUPER_MAGIC, "procfs", err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
libcrun_is_apparmor_enabled (libcrun_error_t *err)
{
  if (apparmor_enabled < 0)
    return crun_make_error (err, 0, "AppArmor not initialized correctly");
  return apparmor_enabled;
}

int
set_apparmor_profile (const char *profile, libcrun_error_t *err)
{
  int ret;

  ret = libcrun_is_apparmor_enabled (err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret)
    {
      cleanup_free char *buf = NULL;

      xasprintf (&buf, "exec %s", profile);

      ret = write_file_and_check_fs_type ("/proc/thread-self/attr/exec", buf, strlen (buf), PROC_SUPER_MAGIC, "procfs", err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

int
read_all_fd (int fd, const char *description, char **out, size_t *len, libcrun_error_t *err)
{
  int ret;
  size_t nread, allocated;
  off_t size = 0;
  cleanup_free char *buf = NULL;

  ret = get_file_size (fd, &size);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error stat'ing file '%s'", description);

  /* NUL terminate the buffer.  */
  allocated = size;
  if (size == 0)
    allocated = 256;
  buf = xmalloc (allocated + 1);
  nread = 0;
  while ((size && nread < (size_t) size) || size == 0)
    {
      ret = TEMP_FAILURE_RETRY (read (fd, buf + nread, allocated - nread));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "error reading from file '%s'", description);

      if (ret == 0)
        break;

      nread += ret;

      allocated += 256;
      buf = xrealloc (buf, allocated + 1);
    }
  buf[nread] = '\0';
  *out = buf;
  buf = NULL;
  if (len)
    *len = nread;
  return 0;
}

int
read_all_file (const char *path, char **out, size_t *len, libcrun_error_t *err)
{
  cleanup_close int fd;

  if (strcmp (path, "-") == 0)
    path = "/dev/stdin";

  fd = TEMP_FAILURE_RETRY (open (path, O_RDONLY));
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "error opening file '%s'", path);

  return read_all_fd (fd, path, out, len, err);
}

int
open_unix_domain_client_socket (const char *path, int dgram, libcrun_error_t *err)
{
  struct sockaddr_un addr;
  int ret;
  cleanup_close int fd = socket (AF_UNIX, dgram ? SOCK_DGRAM : SOCK_STREAM, 0);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "error creating UNIX socket");

  memset (&addr, 0, sizeof (addr));
  if (strlen (path) >= sizeof (addr.sun_path))
    return crun_make_error (err, errno, "invalid path %s specified", path);
  strcpy (addr.sun_path, path);
  addr.sun_family = AF_UNIX;
  ret = connect (fd, (struct sockaddr *) &addr, sizeof (addr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "connect socket to '%s'", path);

  ret = fd;
  fd = -1;

  return ret;
}

int
open_unix_domain_socket (const char *path, int dgram, libcrun_error_t *err)
{
  struct sockaddr_un addr;
  int ret;
  cleanup_close int fd = socket (AF_UNIX, dgram ? SOCK_DGRAM : SOCK_STREAM, 0);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "error creating UNIX socket");

  memset (&addr, 0, sizeof (addr));
  if (strlen (path) >= sizeof (addr.sun_path))
    return crun_make_error (err, errno, "invalid path %s specified", path);
  strcpy (addr.sun_path, path);
  addr.sun_family = AF_UNIX;
  ret = bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bind socket to '%s'", path);

  if (!dgram)
    {
      ret = listen (fd, 1);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "listen on socket");
    }

  ret = fd;
  fd = -1;

  return ret;
}

int
send_fd_to_socket (int server, int fd, libcrun_error_t *err)
{
  int ret;
  struct cmsghdr *cmsg = NULL;
  struct iovec iov[1];
  struct msghdr msg;
  char ctrl_buf[CMSG_SPACE (sizeof (int))];
  char data[1];

  memset (&msg, 0, sizeof (struct msghdr));
  memset (ctrl_buf, 0, CMSG_SPACE (sizeof (int)));

  data[0] = ' ';
  iov[0].iov_base = data;
  iov[0].iov_len = sizeof (data);

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_controllen = CMSG_SPACE (sizeof (int));
  msg.msg_control = ctrl_buf;

  cmsg = CMSG_FIRSTHDR (&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (sizeof (int));

  *((int *) CMSG_DATA (cmsg)) = fd;

  ret = TEMP_FAILURE_RETRY (sendmsg (server, &msg, 0));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sendmsg");
  return 0;
}

int
receive_fd_from_socket (int from, libcrun_error_t *err)
{
  cleanup_close int fd = -1;
  int ret;
  struct iovec iov[1];
  struct msghdr msg;
  char ctrl_buf[CMSG_SPACE (sizeof (int))];
  char data[1];
  struct cmsghdr *cmsg;

  memset (&msg, 0, sizeof (struct msghdr));
  memset (ctrl_buf, 0, CMSG_SPACE (sizeof (int)));

  data[0] = ' ';
  iov[0].iov_base = data;
  iov[0].iov_len = sizeof (data);

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_controllen = CMSG_SPACE (sizeof (int));
  msg.msg_control = ctrl_buf;

  ret = TEMP_FAILURE_RETRY (recvmsg (from, &msg, 0));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "recvmsg");

  cmsg = CMSG_FIRSTHDR (&msg);
  if (cmsg == NULL)
    return crun_make_error (err, 0, "no msg received");
  memcpy (&fd, CMSG_DATA (cmsg), sizeof (fd));

  ret = fd;
  fd = -1;
  return ret;
}

int
create_socket_pair (int *pair, libcrun_error_t *err)
{
  int ret = socketpair (AF_UNIX, SOCK_SEQPACKET, 0, pair);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "socketpair");
  return 0;
}

int
create_signalfd (sigset_t *mask, libcrun_error_t *err)
{
  int ret = signalfd (-1, mask, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "signalfd");
  return ret;
}

int
epoll_helper (int *fds, int *levelfds, libcrun_error_t *err)
{
  struct epoll_event ev;
  cleanup_close int epollfd = -1;
  int ret;

  int *it;
  epollfd = epoll_create1 (0);
  if (UNLIKELY (epollfd < 0))
    return crun_make_error (err, errno, "epoll_create1");

  for (it = fds; *it >= 0; it++)
    {
      ev.events = EPOLLIN;
      ev.data.fd = *it;
      ret = epoll_ctl (epollfd, EPOLL_CTL_ADD, *it, &ev);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "epoll_ctl add '%d'", *it);
    }
  for (it = levelfds; *it >= 0; it++)
    {
      ev.events = EPOLLIN | EPOLLET;
      ev.data.fd = *it;
      ret = epoll_ctl (epollfd, EPOLL_CTL_ADD, *it, &ev);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "epoll_ctl add '%d'", *it);
    }

  ret = epollfd;
  epollfd = -1;
  return ret;
}

int
copy_from_fd_to_fd (int src, int dst, int consume, libcrun_error_t *err)
{
  int ret;
  ssize_t nread;
  do
    {
      cleanup_free char *buffer = NULL;
      ssize_t remaining;

#ifdef HAVE_COPY_FILE_RANGE
      nread = copy_file_range (src, NULL, dst, NULL, 0, 0);
      if (nread < 0 && (errno == EINVAL || errno == EXDEV))
        goto fallback;
      if (consume && nread < 0 && errno == EAGAIN)
        return 0;
      if (nread < 0 && errno == EIO)
        return 0;
      if (UNLIKELY (nread < 0))
        return crun_make_error (err, errno, "copy_file_range");

    fallback:
#endif
# define BUFFER_SIZE 4096

      buffer = xmalloc (BUFFER_SIZE);
      nread = TEMP_FAILURE_RETRY (read (src, buffer, BUFFER_SIZE));
      if (consume && nread < 0 && errno == EAGAIN)
        return 0;
      if (nread < 0 && errno == EIO)
        return 0;
      if (UNLIKELY (nread < 0))
        return crun_make_error (err, errno, "read");

      remaining = nread;
      while (remaining)
        {
          ret = TEMP_FAILURE_RETRY (write (dst, buffer, nread));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write");
          remaining -= ret;
        }
    }
  while (consume && nread);

  return 0;

}

int
run_process (char **args, libcrun_error_t *err)
{
  pid_t pid = fork ();
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "fork");
  if (pid)
    {
      int r, status;
      r = TEMP_FAILURE_RETRY (waitpid (pid, &status, 0));
      if (r < 0)
        return crun_make_error (err, errno, "waitpid");
      if (WIFEXITED (status) || WIFSIGNALED (status))
        return WEXITSTATUS (status);
    }

  execvp (args[0], args);
  _exit (EXIT_FAILURE);
}

int
set_home_env (uid_t id)
{
#ifdef HAVE_FGETPWENT_R
  struct passwd pwd;
  cleanup_free char *buf = NULL;
  long buf_size;
  cleanup_file FILE *stream = NULL;

  buf_size = sysconf (_SC_GETPW_R_SIZE_MAX);
  if (buf_size < 0)
    buf_size = 1024;

  buf = xmalloc (buf_size);

  stream = fopen ("/etc/passwd", "r");
  if (stream == NULL)
    {
      if (errno == ENOENT)
        return 0;
      return -1;
    }

  for (;;)
    {
      int ret;
      struct passwd *ret_pw = NULL;

      ret = fgetpwent_r (stream, &pwd, buf, buf_size, &ret_pw);
      if (UNLIKELY (ret != 0))
        {
          if (errno == ENOENT)
            return 0;

          if (errno != ERANGE)
            return ret;

          buf_size *= 2;
          buf = xrealloc (buf, buf_size);
          continue;
        }

      if (ret_pw && ret_pw->pw_uid == id)
        {
          setenv ("HOME", ret_pw->pw_dir, 1);
          return 0;
        }
    }
  return 0;
#else
  (void) id;
  errno = ENOTSUP;
  return -1;
#endif
}

/*if subuid or subgid exist, take the first range for the user */
static int
getsubidrange (uid_t id, int is_uid, uint32_t *from, uint32_t *len)
{
  cleanup_file FILE *input = NULL;
  cleanup_free char *lineptr = NULL;
  size_t lenlineptr = 0, len_name;
  long buf_size;
  cleanup_free char *buf = NULL;
  const char *name;
  struct passwd pwd;

  buf_size = sysconf (_SC_GETPW_R_SIZE_MAX);
  if (buf_size < 0)
    buf_size = 1024;

  buf = xmalloc (buf_size);
  for (;;)
    {
      int ret;
      struct passwd *ret_pw = NULL;

      ret = getpwuid_r (id, &pwd, buf, buf_size, &ret_pw);
      if (LIKELY (ret == 0))
        {
          if (ret_pw)
            {
              name = ret_pw->pw_name;
              break;
            }
          return -1;
        }

      if (ret < 0 && errno != ERANGE)
        return ret;

      buf_size *= 2;
      buf = xrealloc (buf, buf_size);
    }

  len_name = strlen (name);

  input = fopen (is_uid ? "/etc/subuid" : "/etc/subgid", "r");
  if (input == NULL)
    return -1;

  for (;;)
    {
      char *endptr;
      ssize_t read = getline (&lineptr, &lenlineptr, input);
      if (read < 0)
        return -1;

      if (read < (ssize_t) (len_name + 2))
        continue;

      if (memcmp (lineptr, name, len_name) || lineptr[len_name] != ':')
        continue;

      *from = strtoull (&lineptr[len_name + 1], &endptr, 10);

      if (endptr >= &lineptr[read])
        return -1;

      *len = strtoull (&endptr[1], &endptr, 10);

      return 0;
    }
}

#define MIN(x,y) ((x)<(y)?(x):(y))

size_t
format_default_id_mapping (char **ret, uid_t container_id, uid_t host_id, int is_uid)
{
  uint32_t from, available;
  cleanup_free char *buffer = NULL;
  size_t written = 0;

  *ret = NULL;

  if (getsubidrange (host_id, is_uid, &from, &available) < 0)
    return 0;

  /* More than enough space for all the mappings.  */
  buffer = xmalloc (15 * 5 * 3);

  if (container_id > 0)
    {
      uint32_t used = MIN (container_id, available);
      written += sprintf (buffer + written, "%d %d %d\n", 0, from, used);
      from += used;
      available -= used;
    }

  /* Host ID -> Container ID.  */
  written += sprintf (buffer + written, "%d %d 1\n", container_id, host_id);

  /* Last mapping: use any id that is left.  */
  if (available)
    written += sprintf (buffer + written, "%d %d %d\n", container_id + 1, from, available);

  *ret = buffer;
  buffer = NULL;
  return written;
}

/* will leave SIGCHLD blocked if TIMEOUT is used.  */
int
run_process_with_stdin_timeout_envp (char *path,
                                     char **args,
                                     const char *cwd,
                                     int timeout,
                                     char **envp,
                                     char *stdin,
                                     size_t stdin_len,
                                     libcrun_error_t *err)
{
  int stdin_pipe[2];
  pid_t pid;
  int ret;
  cleanup_close int pipe_r = -1;
  cleanup_close int pipe_w = -1;
  sigset_t mask;

  ret = pipe (stdin_pipe);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipe_r = stdin_pipe[0];
  pipe_w = stdin_pipe[1];

  if (timeout > 0)
    {
      sigaddset (&mask, SIGCHLD);
      ret = sigprocmask (SIG_BLOCK, &mask, NULL);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "sigprocmask");
    }

  pid = fork ();
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "fork");

  if (pid)
    {
      int r, status;

      close_and_reset (&pipe_r);

      ret = TEMP_FAILURE_RETRY (write (pipe_w, stdin, stdin_len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "writing to pipe");

      close_and_reset (&pipe_w);

      if (timeout)
        {
          time_t start = time (NULL);
          time_t now;
          for (now = start; now - start < timeout; now = time (NULL))
            {
              siginfo_t info;
              int elapsed = now - start;
              struct timespec ts_timeout = { .tv_sec = timeout - elapsed, .tv_nsec = 0 };

              ret = sigtimedwait (&mask, &info, &ts_timeout);
              if (UNLIKELY (ret < 0 && errno != EAGAIN))
                return crun_make_error (err, errno, "sigtimedwait");

              if (info.si_signo == SIGCHLD && info.si_pid == pid)
                goto read_waitpid;

              if (ret < 0 && errno == EAGAIN)
                goto timeout;
            }
 timeout:
          kill (pid, SIGKILL);
          return crun_make_error (err, 0, "timeout expired for '%s'", path);
        }

 read_waitpid:
      r = TEMP_FAILURE_RETRY (waitpid (pid, &status, 0));
      if (r < 0)
        return crun_make_error (err, errno, "waitpid");
      if (WIFEXITED (status))
        return WEXITSTATUS (status);
      if (WIFSIGNALED (status))
        return 127 + WTERMSIG (status);
    }
  else
    {
      char *tmp_args[] = {path, NULL};
      int out = open ("/dev/null", O_WRONLY);

      if (UNLIKELY (out < 0))
        _exit (EXIT_FAILURE);

      TEMP_FAILURE_RETRY (close (pipe_w));
      dup2 (pipe_r, 0);
      TEMP_FAILURE_RETRY (close (pipe_r));

      dup2 (out, 1);
      dup2 (out, 2);
      TEMP_FAILURE_RETRY (close (out));

      if (args == NULL)
        args = tmp_args;

      if (cwd && chdir (cwd) < 0)
        _exit (EXIT_FAILURE);

      execvpe (path, args, envp);
      _exit (EXIT_FAILURE);
    }
  return -1;
}

int
close_fds_ge_than (int n, libcrun_error_t *err)
{
  cleanup_close int cfd = -1;
  cleanup_dir DIR *dir = NULL;
  int ret;
  int fd;
  struct statfs sfs;
  struct dirent *next;

  cfd = open ("/proc/self/fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  if (UNLIKELY (cfd < 0))
    return crun_make_error (err, errno, "open /proc/self/fd");

  ret = fstatfs (cfd, &sfs);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "statfs '/proc/self/fd'");

  if (sfs.f_type != PROC_SUPER_MAGIC)
    return crun_make_error (err, 0, "the path '/proc/self/fd' is not on file system type 'procfs'");

  dir = fdopendir (cfd);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, errno, "cannot fdopendir /proc/self/fd");

  /* Now it is owned by dir.  */
  cfd = -1;

  fd = dirfd (dir);
  for (next = readdir (dir); next; next = readdir (dir))
    {
      int val;
      const char *name = next->d_name;
      if (name[0] == '.')
        continue;

      val = strtoll (name, NULL, 10);
      if (val < n || val == fd)
        continue;

      ret = fcntl (val, F_SETFD, FD_CLOEXEC);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "cannot set CLOEXEC fd for '/proc/self/fd/%s'", name);
    }
  return 0;
}

void
get_current_timestamp (char *out)
{
  struct timeval tv;
  struct tm now;
  char timestamp[64];

  gettimeofday (&tv, NULL);
  gmtime_r (&tv.tv_sec, &now);
  strftime (timestamp, sizeof (timestamp), "%Y-%m-%dT%H:%M:%S", &now);

  sprintf (out, "%s.%09ldZ", timestamp, tv.tv_usec);
}

int
set_blocking_fd (int fd, int blocking, libcrun_error_t *err)
{
  int ret, flags = fcntl (fd, F_GETFL, 0);
  if (UNLIKELY (flags < 0))
    return crun_make_error (err, errno, "fcntl");

  ret = fcntl (fd, F_SETFL, blocking ? flags & ~O_NONBLOCK : flags | O_NONBLOCK);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fcntl");
  return 0;
}

int
parse_json_file (yajl_val *out, const char *jsondata, struct parser_context *ctx arg_unused, libcrun_error_t *err)
{
    char errbuf[1024];

    *err = NULL;

    *out = yajl_tree_parse (jsondata, errbuf, sizeof (errbuf));
    if (*out == NULL)
      return crun_make_error (err, 0, "cannot parse the data: '%s'", errbuf);

    return 0;
}

int
has_prefix (const char *str, const char *prefix)
{
  size_t prefix_len = strlen (prefix);
  return strlen (str) >= prefix_len && memcmp (str, prefix, prefix_len) == 0;
}

static int
check_access (const char *path)
{
  int ret;
  mode_t mode;

  ret = eaccess (path, X_OK);
  if (ret < 0)
    return ret;

  ret = get_file_type (&mode, false, path);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! S_ISREG (mode))
    {
      errno = EPERM;
      return -1;
    }

  return 0;
}

const char *
find_executable (const char *executable_path, const char *cwd)
{
  cleanup_free char *cwd_executable_path = NULL;
  cleanup_free char *tmp = NULL;
  char path[PATH_MAX + 1];
  int last_error = ENOENT;
  char *it, *end;
  int ret;

  if (executable_path == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  if (executable_path[0] == '.')
    {
      cleanup_free char *cwd_allocated = NULL;

      if (cwd == NULL)
        {
          cwd_allocated = get_current_dir_name ();
          if (cwd_allocated == NULL)
            OOM ();

          cwd = cwd_allocated;
        }

      /* Make sure the path starts with a '/' so it will hit the check
         for absolute paths.  */
      xasprintf (&cwd_executable_path, "%s%s/%s", cwd[0] == '/' ? "" : "/", cwd, executable_path);
      executable_path = cwd_executable_path;
    }

  /* Absolute path.  It doesn't need to lookup $PATH.  */
  if (executable_path[0] == '/')
    {
      ret = check_access (executable_path);
      if (ret == 0)
        return xstrdup (executable_path);
      return NULL;
    }

  end = tmp = xstrdup (getenv ("PATH"));

  while ((it = strsep (&end, ":")))
    {
      size_t len;

      if (it == end)
        it = ".";

      len = snprintf (path, PATH_MAX, "%s/%s", it, executable_path);
      if (len == PATH_MAX)
        continue;

      ret = check_access (path);
      if (ret == 0)
        return xstrdup (path);

      if (errno == ENOENT)
        continue;

      last_error = errno;
    }

  errno = last_error;
  return NULL;
}

#ifdef HAVE_FGETXATTR

static ssize_t
safe_read_xattr (char **ret, int sfd, const char *srcname, const char *name, size_t initial_size, libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  ssize_t current_size;
  ssize_t s;

  current_size = (ssize_t) initial_size;
  buffer = xmalloc (current_size + 1);

  while (1)
    {
      s = fgetxattr (sfd, name, buffer, current_size);
      if (UNLIKELY (s < 0))
        return crun_make_error (err, errno, "get xattr %s from %s", name, srcname);

      if (s < current_size)
        break;

      current_size *= 2;
      buffer = xrealloc (buffer, current_size + 1);
    }

  if (s <= 0)
    return s;

  buffer[s] = '\0';

  /* Change owner.  */
  *ret = buffer;
  buffer = NULL;

  return s;
}

static ssize_t
copy_xattr (int sfd, int dfd, const char *srcname, const char *destname, libcrun_error_t *err)
{
  cleanup_free char *buf = NULL;
  ssize_t xattr_len;
  char *it;

  xattr_len = flistxattr (sfd, NULL, 0);
  if (UNLIKELY (xattr_len < 0))
    {
      if (errno == ENOTSUP)
        return 0;

      return crun_make_error (err, errno, "get xattr list for %s", srcname);
    }


  if (xattr_len == 0)
    return 0;

  buf = xmalloc (xattr_len + 1);

  xattr_len = flistxattr (sfd, buf, xattr_len + 1);
  if (UNLIKELY (xattr_len < 0))
    return crun_make_error (err, errno, "get xattr list for %s", srcname);

  for (it = buf; it - buf < xattr_len; it += strlen (it) + 1)
    {
      cleanup_free char *v = NULL;
      ssize_t s;

      s = safe_read_xattr (&v, sfd, srcname, it, 256, err);
      if (UNLIKELY (s < 0))
        return s;

      s = fsetxattr (dfd, it, v, s, 0);
      if (UNLIKELY (s < 0))
        {
          if (errno == EINVAL || errno == EOPNOTSUPP)
            continue;

          return crun_make_error (err, errno, "set xattr for %s", destname);
        }
    }

  return 0;
}

#endif

static
int copy_rec_stat_file_at (int dfd, const char *path, mode_t *mode, off_t *size, dev_t *rdev, uid_t *uid, gid_t *gid)
{
  struct stat st;
  int ret;

#ifdef HAVE_STATX
  struct statx stx;

  ret = statx (dfd, path, AT_SYMLINK_NOFOLLOW | AT_STATX_DONT_SYNC, STATX_TYPE | STATX_MODE | STATX_SIZE | STATX_UID | STATX_GID, &stx);
  if (UNLIKELY (ret < 0))
    {
      if (errno == ENOSYS || errno == EINVAL)
        goto fallback;

      return ret;
    }

  *mode = stx.stx_mode;
  *size = stx.stx_size;
  *rdev = makedev (stx.stx_rdev_major, stx.stx_rdev_minor);
  *uid = stx.stx_uid;
  *gid = stx.stx_gid;

  return ret;

 fallback:
#endif
  ret = fstatat (dfd, path, &st, AT_SYMLINK_NOFOLLOW);

  *mode = st.st_mode;
  *size = st.st_size;
  *rdev = st.st_rdev;
  *uid = st.st_uid;
  *gid = st.st_gid;

  return ret;
}

int
copy_recursive_fd_to_fd (int srcdirfd, int destdirfd, const char *srcname, const char *destname, libcrun_error_t *err)
{
  cleanup_close int dfd = destdirfd;
  cleanup_dir DIR *dsrcfd = NULL;
  struct dirent *de;

  dsrcfd = fdopendir (srcdirfd);
  if (UNLIKELY (dsrcfd == NULL))
    {
      TEMP_FAILURE_RETRY (close (srcdirfd));
      return crun_make_error (err, errno, "cannot open directory %s", destname);
    }

  for (de = readdir (dsrcfd); de; de = readdir (dsrcfd))
    {
      cleanup_close int srcfd = -1;
      cleanup_close int destfd = -1;
      cleanup_free char *target_buf = NULL;
      ssize_t buf_size;
      ssize_t size;
      int ret;
      mode_t mode;
      off_t st_size;
      dev_t rdev;
      uid_t uid;
      gid_t gid;

      if (strcmp (de->d_name, ".") == 0 ||
          strcmp (de->d_name, "..") == 0)
        continue;

      ret = copy_rec_stat_file_at (dirfd (dsrcfd), de->d_name, &mode, &st_size, &rdev, &uid, &gid);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "stat %s/%s", srcname, de->d_name);

      switch (mode & S_IFMT)
        {
        case S_IFREG:
          srcfd = openat (dirfd (dsrcfd), de->d_name, O_NONBLOCK | O_RDONLY);
          if (UNLIKELY (srcfd < 0))
            return crun_make_error (err, errno, "open %s/%s", srcname, de->d_name);

          destfd = openat (destdirfd, de->d_name, O_RDWR | O_CREAT, 0777);
          if (UNLIKELY (destfd < 0))
            return crun_make_error (err, errno, "open %s/%s", destname, de->d_name);

          ret = copy_from_fd_to_fd (srcfd, destfd, 0, err);
          if (UNLIKELY (ret < 0))
            return ret;

#ifdef HAVE_FGETXATTR
          ret = (int) copy_xattr (srcfd, destfd, de->d_name, de->d_name, err);
          if (UNLIKELY (ret < 0))
            return ret;
#endif

          TEMP_FAILURE_RETRY (close (destfd));
          destfd = -1;
          break;

        case S_IFDIR:
          ret = mkdirat (destdirfd, de->d_name, mode);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "mkdir %s/%s", destname, de->d_name);

          srcfd = openat (dirfd (dsrcfd), de->d_name, O_DIRECTORY);
          if (UNLIKELY (srcfd < 0))
            return crun_make_error (err, errno, "open directory %s/%s", srcname, de->d_name);

          destfd = openat (destdirfd, de->d_name, O_DIRECTORY);
          if (UNLIKELY (destfd < 0))
            return crun_make_error (err, errno, "open directory %s/%s", srcname, de->d_name);

#ifdef HAVE_FGETXATTR
          ret = (int) copy_xattr (srcfd, destfd, de->d_name, de->d_name, err);
          if (UNLIKELY (ret < 0))
            return ret;
#endif

          ret = copy_recursive_fd_to_fd (srcfd, destfd, de->d_name, de->d_name, err);
          srcfd = destfd = -1;
          if (UNLIKELY (ret < 0))
            return ret;
          break;

        case S_IFLNK:
          buf_size = st_size + 1;
          target_buf = xmalloc (buf_size);

          do
            {
              buf_size += 1024;

              target_buf = xrealloc (target_buf, buf_size);

              size = readlinkat (dirfd (dsrcfd), de->d_name, target_buf, buf_size);
              if (UNLIKELY (size < 0))
                return crun_make_error (err, errno, "readlink %s/%s", srcname, de->d_name);
            }
          while (size == buf_size);

          ret = symlinkat (target_buf, destdirfd, de->d_name);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "create symlink %s/%s", destname, de->d_name);
          break;

        case S_IFBLK:
        case S_IFCHR:
        case S_IFIFO:
        case S_IFSOCK:
          ret = mknodat (destdirfd, de->d_name, mode, rdev);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "create special file %s/%s", destname, de->d_name);
          break;
        }

      ret = fchownat (destdirfd, de->d_name, uid, gid, AT_SYMLINK_NOFOLLOW);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "chown %s/%s", destname, de->d_name);

      /*
       * ALLPERMS is not defined by POSIX
       */
#ifndef ALLPERMS
# define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)
#endif

      ret = fchmodat (destdirfd, de->d_name, mode & ALLPERMS, AT_SYMLINK_NOFOLLOW);
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOTSUP)
            {
              char proc_path[32];
              cleanup_close int fd = -1;

              fd = openat (destdirfd, de->d_name, O_PATH | O_NOFOLLOW);
              if (UNLIKELY (fd < 0))
                return crun_make_error (err, errno, "open %s/%s", destname, de->d_name);

              sprintf (proc_path, "/proc/self/fd/%d", fd);
              ret = chmod (proc_path, mode & ALLPERMS);
            }

          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "chmod %s/%s", destname, de->d_name);
        }
    }

  return 0;
}

const char *
find_annotation (libcrun_container_t *container, const char *name)
{
  size_t i;

  if (container->container_def->annotations == NULL)
    return NULL;

  for (i = 0; i < container->container_def->annotations->len; i++)
    {
      if (strcmp (container->container_def->annotations->keys[i], name) == 0)
        return container->container_def->annotations->values[i];
    }

  return NULL;
}
