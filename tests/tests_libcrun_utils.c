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

#include <libcrun/error.h>
#include <libcrun/utils.h>
#include <libcrun/cgroup.h>
#include <libcrun/cgroup-systemd.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

typedef int (*test) ();

static int
test_socket_pair ()
{
  libcrun_error_t err = NULL;
  int fds[2];
  __attribute__ ((unused)) cleanup_close int fd0 = -1;
  __attribute__ ((unused)) cleanup_close int fd1 = -1;
  char buffer[256];
  int ret = create_socket_pair (fds, &err);
  if (ret < 0)
    return -1;

  fd0 = fds[0];
  fd1 = fds[1];

  if (err != NULL)
    return -1;

  ret = write (fds[0], "HELLO", 6);
  if (ret != 6)
    return -1;

  ret = read (fds[1], buffer, sizeof (buffer));
  if (ret != 6)
    return -1;
  if (strcmp (buffer, "HELLO") != 0)
    return -1;

  ret = write (fds[1], "WORLD", 6);
  if (ret != 6)
    return -1;

  ret = read (fds[0], buffer, sizeof (buffer));
  if (ret != 6)
    return -1;

  if (strcmp (buffer, "WORLD") != 0)
    return -1;

  return 0;
}

static int
test_send_receive_fd ()
{
  libcrun_error_t err = NULL;
  int fds[2], pipes[2];
  cleanup_close int fd0 = -1;
  cleanup_close int fd1 = -1;
  pid_t pid;
  int ret = create_socket_pair (fds, &err);
  if (ret < 0)
    return -1;

  fd0 = fds[0];
  fd1 = fds[1];

  if (err != NULL)
    return -1;

  pid = fork ();
  if (pid < 0)
    return -1;

  if (pid)
    {
      cleanup_close int pipefd0 = -1;
      cleanup_close int pipefd1 = -1;
      char buffer[256];
      const char *test_string = "TEST STRING";
      if (pipe (pipes) < 0)
        return -1;

      pipefd0 = pipes[0];
      pipefd1 = pipes[1];

      close (fd0);
      fd0 = -1;

      if (send_fd_to_socket (fd1, pipefd0, &err) < 0)
        return -1;

      if (write (pipefd1, test_string, strlen (test_string) + 1) < 0)
        return -1;

      ret = read (fd1, buffer, sizeof (buffer));
      if (ret < 0)
        return -1;

      if (ret != (int) strlen (test_string) + 1)
        return -1;

      return strcmp (buffer, test_string);
    }
  else
    {
      char buffer[256];
      int ret, fd = receive_fd_from_socket (fd0, &err);
      if (fd < 0)
        _exit (1);

      close (fd1);
      fd1 = -1;

      ret = read (fd, buffer, sizeof (buffer));
      if (ret <= 0)
        return -1;
      if (write (fd0, buffer, ret) < 0)
        return -1;

      _exit (0);
    }
  return 0;
}

static int
test_run_process ()
{
  libcrun_error_t err = NULL;
  {
    char *args[] = { "/bin/true", NULL };
    if (run_process (args, &err) != 0)
      return -1;
  }

  {
    char *args[] = { "/bin/false", NULL };
    if (run_process (args, &err) <= 0)
      return -1;
    if (err != NULL)
      return -1;
  }

  {
    char *args[] = { "/does/not/exist", NULL };
    int r = run_process (args, &err);
    if (r <= 0)
      return -1;
    if (err != NULL)
      return -1;
  }

  return 0;
}

static int
test_dir_p ()
{
  libcrun_error_t err;
  if (crun_dir_p ("/usr", false, &err) <= 0)
    return -1;
  if (crun_dir_p ("/dev/zero", false, &err) != 0)
    return -1;
  if (crun_dir_p ("/hopefully/does/not/really/exist", false, &err) >= 0)
    return -1;
  return 0;
}

static int
test_write_read_file ()
{
  libcrun_error_t err = NULL;
  cleanup_free char *name = NULL;
  size_t len;
  size_t i;
  int ret, failed = 0;
  size_t max = 1 << 10;
  cleanup_free char *written = xmalloc (max);

  xasprintf (&name, "tests/write-file-%i", getpid ());

  for (i = 0; i < max; i++)
    written[i] = i;

  for (i = 1; i <= max; i *= 2)
    {
      cleanup_free char *read_buf = NULL;

      ret = write_file (name, written, i, &err);
      if (ret < 0)
        {
          failed = 1;
          break;
        }

      ret = read_all_file (name, &read_buf, &len, &err);
      if (ret < 0)
        {
          failed = 1;
          break;
        }

      if (len != i)
        {
          failed = 1;
          break;
        }

      if (memcmp (read_buf, written, len) != 0)
        {
          failed = 1;
          break;
        }
    }

  unlink (name);
  return failed ? -1 : 0;
}

static int
test_crun_path_exists ()
{

  libcrun_error_t err = NULL;
  if (crun_path_exists ("/dev/null", &err) <= 0)
    return -1;
  if (crun_path_exists ("/usr/foo/bin/ls", &err) != 0)
    return -1;
  if (crun_path_exists ("/proc/sysrq-trigger", &err) != 1)
    return -1;
  return 0;
}

static int
test_append_paths ()
{
#define PROLOGUE()               \
  cleanup_free char *out = NULL; \
  libcrun_error_t err = NULL;    \
  int ret;

#define EXPECT_STRING(exp)         \
  {                                \
    if (ret < 0 || out == NULL)    \
      {                            \
        crun_error_release (&err); \
        return ret;                \
      }                            \
    if (strcmp (out, exp))         \
      return -1;                   \
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "/sys/fs/cgroup/", "memory", "some/path", NULL);
    EXPECT_STRING ("/sys/fs/cgroup/memory/some/path");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "/sys/fs/cgroup", "memory", "some/path", NULL);
    EXPECT_STRING ("/sys/fs/cgroup/memory/some/path");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "/sys/fs/cgroup////////", "memory////////", "some/path//////", NULL);
    EXPECT_STRING ("/sys/fs/cgroup/memory/some/path");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "/sys/fs/cgroup////////", "memory////////", "///////some/path//////", NULL);
    EXPECT_STRING ("/sys/fs/cgroup/memory/some/path");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "", "//", "", "", "", NULL);
    EXPECT_STRING ("/");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "///", "/", "", "///", "a", NULL);
    EXPECT_STRING ("/a");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "////", "/////", "///", "", "", NULL);
    EXPECT_STRING ("/");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "", "", "", "", "", NULL);
    EXPECT_STRING ("");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "", "///sys/fs/cgroup////////", "", "some/path", NULL);
    EXPECT_STRING ("/sys/fs/cgroup/some/path");
  }
  {
    PROLOGUE ();
    ret = append_paths (&out, &err, "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d",
                        "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d",
                        "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", NULL);
    if (ret == 0)
      return -1;
    crun_error_release (&err);
  }
  return 0;
}

#ifdef HAVE_SYSTEMD
static int
test_parse_sd_array ()
{
  char *out, *next;
  libcrun_error_t err = NULL;
  {
    cleanup_free char *s = xstrdup ("       'firewalld.service'    ");
    if (parse_sd_array (s, &out, &next, &err) < 0)
      {
        crun_error_release (&err);
        return -1;
      }
    if (strcmp (out, "firewalld.service"))
      return -1;
    if (next != NULL)
      return -1;
  }
  {
    cleanup_free char *s = xstrdup ("'fir\\ewalld.ser\\vi\\ce']");
    if (parse_sd_array (s, &out, &next, &err) < 0)
      {
        crun_error_release (&err);
        return -1;
      }
    if (strcmp (out, "firewalld.service"))
      return -1;
    if (next != NULL)
      return -1;
  }
  {
    cleanup_free char *s = xstrdup ("'fi\\rew\\alld.s\\erv\\ice', 'foo.service']");
    if (parse_sd_array (s, &out, &next, &err) < 0)
      {
        crun_error_release (&err);
        return -1;
      }
    if (strcmp (out, "firewalld.service"))
      return -1;
    if (strcmp (next, " 'foo.service']"))
      return -1;
  }
  return 0;
}
#endif

static void
run_and_print_test_result (const char *name, int id, test t)
{
  int ret = t ();
  if (ret == 0)
    printf ("ok %d - %s\n", id, name);
  else if (ret == 77)
    printf ("ok %d - %s #SKIP\n", id, name);
  else
    printf ("not ok %d - %s\n", id, name);
}

#define RUN_TEST(T)                            \
  do                                           \
    {                                          \
      run_and_print_test_result (#T, id++, T); \
  } while (0)

int
main ()
{
  int id = 1;
#ifdef HAVE_SYSTEMD
  printf ("1..8\n");
#else
  printf ("1..7\n");
#endif
  RUN_TEST (test_crun_path_exists);
  RUN_TEST (test_write_read_file);
  RUN_TEST (test_run_process);
  RUN_TEST (test_dir_p);
  RUN_TEST (test_socket_pair);
  RUN_TEST (test_send_receive_fd);
  RUN_TEST (test_append_paths);
#ifdef HAVE_SYSTEMD
  RUN_TEST (test_parse_sd_array);
#endif
  return 0;
}
