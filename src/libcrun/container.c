/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <ocispec/runtime_spec_schema_config_schema.h>
#include <stdbool.h>
#include "container.h"
#include "utils.h"
#include "json_gen_utils.h"
#include "seccomp.h"
#include "mempolicy.h"
#ifdef HAVE_SECCOMP
#  include <seccomp.h>
#endif
#include "scheduler.h"
#include "seccomp_notify.h"
#include "custom-handler.h"
#include <stdbool.h>
#include <argp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include "status.h"
#include "mount_flags.h"
#include "linux.h"
#include "terminal.h"
#include "io_priority.h"
#include "cgroup.h"
#include "cgroup-utils.h"
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#ifdef HAVE_CAP
#  include <sys/capability.h>
#endif
#include <sys/ioctl.h>
#include <termios.h>
#include <grp.h>
#include <libgen.h>
#include <git-version.h>

#ifdef HAVE_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif

#include <json-c/json.h>
#include <ocispec/json_common.h>

enum
{
  SYNC_SOCKET_SYNC_MESSAGE,
  SYNC_SOCKET_ERROR_MESSAGE,
  SYNC_SOCKET_WARNING_MESSAGE,
  SYNC_SOCKET_DEBUG_MESSAGE,
};

struct container_entrypoint_s
{
  libcrun_container_t *container;
  libcrun_context_t *context;
  int has_terminal_socket_pair;
  int terminal_socketpair[2];

  /* Used by log_write_to_sync_socket.  */
  int sync_socket;

  int seccomp_fd;
  int seccomp_receiver_fd;
  int console_socket_fd;

  int hooks_out_fd;
  int hooks_err_fd;

  struct custom_handler_instance_s *custom_handler;
};

struct sync_socket_message_s
{
  int type;
  int error_value;
  char message[512];
};

typedef runtime_spec_schema_defs_hook hook;

// linux hooks
char *hooks[] = {
  "prestart",
  "createRuntime",
  "createContainer",
  "startContainer",
  "poststart",
  "poststop"
};

// linux namespaces
static char *namespaces[] = {
  "cgroup",
  "ipc",
  "mount",
  "network",
  "pid",
  "user",
  "uts"
};

static char *actions[] = {
  "SCMP_ACT_ALLOW",
  "SCMP_ACT_ERRNO",
  "SCMP_ACT_KILL",
  "SCMP_ACT_KILL_PROCESS",
  "SCMP_ACT_KILL_THREAD",
  "SCMP_ACT_LOG",
  "SCMP_ACT_NOTIFY",
  "SCMP_ACT_TRACE",
  "SCMP_ACT_TRAP"
};

static char *operators[] = {
  "SCMP_CMP_NE",
  "SCMP_CMP_LT",
  "SCMP_CMP_LE",
  "SCMP_CMP_EQ",
  "SCMP_CMP_GE",
  "SCMP_CMP_GT",
  "SCMP_CMP_MASKED_EQ",
};

static char *archs[] = {
  "SCMP_ARCH_AARCH64",
  "SCMP_ARCH_ARM",
  "SCMP_ARCH_MIPS",
  "SCMP_ARCH_MIPS64",
  "SCMP_ARCH_MIPS64N32",
  "SCMP_ARCH_MIPSEL",
  "SCMP_ARCH_MIPSEL64",
  "SCMP_ARCH_MIPSEL64N32",
  "SCMP_ARCH_PPC",
  "SCMP_ARCH_PPC64",
  "SCMP_ARCH_PPC64LE",
  "SCMP_ARCH_RISCV64",
  "SCMP_ARCH_S390",
  "SCMP_ARCH_S390X",
  "SCMP_ARCH_X32",
  "SCMP_ARCH_X86",
  "SCMP_ARCH_X86_64"
};

static char *mempolicy_modes[] = {
  "MPOL_DEFAULT",
  "MPOL_PREFERRED",
  "MPOL_BIND",
  "MPOL_INTERLEAVE",
  "MPOL_LOCAL",
  "MPOL_PREFERRED_MANY",
  "MPOL_WEIGHTED_INTERLEAVE"
};

static char *mempolicy_flags[] = {
  "MPOL_F_NUMA_BALANCING",
  "MPOL_F_RELATIVE_NODES",
  "MPOL_F_STATIC_NODES"
};

static char *potentially_unsafe_annotations[] = {
  "module.wasm.image/variant",
  "io.kubernetes.cri.container-type",
  "run.oci.",
  "org.criu.",
  "krun.",
};

#define SYNC_SOCKET_MESSAGE_LEN(x, l) (offsetof (struct sync_socket_message_s, message) + l)

static int
sync_socket_write_msg (int fd, int verbosity, int err_value, const char *log_msg)
{
  int ret;
  size_t err_len;
  struct sync_socket_message_s msg;
  switch (verbosity)
    {
    case LIBCRUN_VERBOSITY_DEBUG:
      msg.type = SYNC_SOCKET_DEBUG_MESSAGE;
      break;
    case LIBCRUN_VERBOSITY_WARNING:
      msg.type = SYNC_SOCKET_WARNING_MESSAGE;
      break;
    case LIBCRUN_VERBOSITY_ERROR:
      msg.type = SYNC_SOCKET_ERROR_MESSAGE;
      break;
    }
  msg.error_value = err_value;

  if (fd < 0)
    return 0;

  err_len = strlen (log_msg);
  if (err_len >= sizeof (msg.message))
    err_len = sizeof (msg.message) - 1;

  memcpy (msg.message, log_msg, err_len);
  msg.message[err_len] = '\0';

  ret = TEMP_FAILURE_RETRY (write (fd, &msg, SYNC_SOCKET_MESSAGE_LEN (msg, err_len + 1)));
  if (UNLIKELY (ret < 0))
    return -1;

  return 0;
}

static int
sync_socket_write_error (int fd, libcrun_error_t *out_err)
{
  if (fd < 0)
    return 0;
  return sync_socket_write_msg (fd, false, (*out_err)->status, (*out_err)->msg);
}

static void
log_write_to_sync_socket (int errno_, const char *msg, int verbosity, void *arg)
{
  struct container_entrypoint_s *entrypoint_args = arg;
  int fd = entrypoint_args->sync_socket;

  if (fd < 0)
    return;

  if (sync_socket_write_msg (fd, verbosity, errno_, msg) < 0)
    log_write_to_stderr (errno_, msg, verbosity, arg);
}

static bool
is_memory_limit_too_low (runtime_spec_schema_config_schema *def)
{
  const long memory_limit_too_low = 1024 * 1024;

  if (def->linux == NULL || def->linux->resources == NULL)
    return false;

  if (def->linux->resources->memory
      && def->linux->resources->memory->limit_present
      && def->linux->resources->memory->limit < memory_limit_too_low)
    return true;

  if (def->linux->resources->unified)
    {
      size_t i;

      for (i = 0; i < def->linux->resources->unified->len; i++)
        if (strcmp (def->linux->resources->unified->keys[i], "memory.max") == 0)
          {
            long limit;

            errno = 0;
            limit = strtol (def->linux->resources->unified->values[i], NULL, 10);
            if (errno != 0)
              return false;
            if (limit < memory_limit_too_low)
              return true;
          }
    }

  return false;
}

static int
sync_socket_wait_sync (libcrun_context_t *context, int fd, bool flush, libcrun_error_t *err)
{
  struct sync_socket_message_s msg;

  if (fd < 0)
    return 0;

  while (true)
    {
      int ret;

      ret = TEMP_FAILURE_RETRY (read (fd, &msg, sizeof (msg)));
      if (UNLIKELY (ret < 0))
        {
          if (flush)
            return 0;
          return crun_make_error (err, errno, "read from sync socket");
        }

      if (ret == 0)
        {
          if (flush)
            return 0;

          return crun_make_error (err, 0, "read from the init process");
        }

      if (! flush && msg.type == SYNC_SOCKET_SYNC_MESSAGE)
        return 0;
      else if (msg.type == SYNC_SOCKET_DEBUG_MESSAGE)
        {
          if (context)
            context->output_handler (msg.error_value, msg.message, LIBCRUN_VERBOSITY_DEBUG, context->output_handler_arg);
          continue;
        }
      else if (msg.type == SYNC_SOCKET_WARNING_MESSAGE)
        {
          if (context)
            context->output_handler (msg.error_value, msg.message, LIBCRUN_VERBOSITY_WARNING, context->output_handler_arg);
          continue;
        }
      else if (msg.type == SYNC_SOCKET_ERROR_MESSAGE)
        return crun_make_error (err, msg.error_value, "%s", msg.message);
    }
}

static int
sync_socket_send_sync (int fd, bool flush_errors, libcrun_error_t *err)
{
  int ret;
  struct sync_socket_message_s msg = {
    0,
  };
  msg.type = SYNC_SOCKET_SYNC_MESSAGE;

  if (fd < 0)
    return 0;

  ret = TEMP_FAILURE_RETRY (write (fd, &msg, SYNC_SOCKET_MESSAGE_LEN (msg, 0)));
  if (UNLIKELY (ret < 0))
    {
      if (flush_errors)
        {
          int saved_errno = errno;
          ret = TEMP_FAILURE_RETRY (read (fd, &msg, sizeof (msg)));
          if (ret >= 0 && msg.type == SYNC_SOCKET_ERROR_MESSAGE)
            return crun_make_error (err, msg.error_value, "%s", msg.message);
          errno = saved_errno;
        }
      return crun_make_error (err, errno, "write to sync socket");
    }

  return 0;
}

static libcrun_container_t *
make_container (runtime_spec_schema_config_schema *container_def, const char *path, const char *config)
{
  libcrun_container_t *container = xmalloc0 (sizeof (*container));
  container->container_def = container_def;

  container->host_uid = geteuid ();
  container->host_gid = getegid ();
  container->proc_fd = -1;

  container->annotations = make_string_map_from_json (container_def->annotations);

  if (path)
    container->config_file = xstrdup (path);
  if (config)
    container->config_file_content = xstrdup (config);

  return container;
}

libcrun_container_t *
libcrun_container_load_from_memory (const char *json, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = runtime_spec_schema_config_schema_parse_data (json, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load: `%s`", oci_error);
      return NULL;
    }
  return make_container (container_def, NULL, json);
}

libcrun_container_t *
libcrun_container_load_from_file (const char *path, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *container_def;
  cleanup_free char *oci_error = NULL;
  libcrun_debug ("Loading container from config file: `%s`", path);
  container_def = runtime_spec_schema_config_schema_parse_file (path, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load `%s`: %s", path, oci_error);
      return NULL;
    }
  return make_container (container_def, path, NULL);
}

void
libcrun_container_free (libcrun_container_t *ctr)
{
  if (ctr == NULL)
    return;

  if (ctr->cleanup_private_data)
    ctr->cleanup_private_data (ctr->private_data);

  if (ctr->container_def)
    free_runtime_spec_schema_config_schema (ctr->container_def);

  free_string_map (ctr->annotations);

  if (ctr->proc_fd >= 0)
    close (ctr->proc_fd);

  free (ctr->config_file_content);
  free (ctr->config_file);
  free (ctr);
}

static int
block_signals (libcrun_error_t *err)
{
  int ret;
  sigset_t mask;
  sigfillset (&mask);
  ret = sigprocmask (SIG_BLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");
  return 0;
}

static int
unblock_signals (libcrun_error_t *err)
{
  int i;
  int ret;
  sigset_t mask;
  struct sigaction act = {};

  sigfillset (&mask);
  ret = sigprocmask (SIG_UNBLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");

  act.sa_handler = SIG_DFL;
  for (i = 0; i < NSIG; i++)
    {
      ret = sigaction (i, &act, NULL);
      if (ret < 0 && errno != EINVAL)
        return crun_make_error (err, errno, "sigaction");
    }

  return 0;
}

/* must be used on the host before pivot_root(2).  */
static int
initialize_security (libcrun_container_t *container, runtime_spec_schema_config_schema_process *proc, libcrun_error_t *err)
{
  int ret;

  ret = libcrun_init_caps (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (proc == NULL))
    return 0;

  if (proc->apparmor_profile)
    {
      ret = libcrun_initialize_apparmor (err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_initialize_selinux (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

/* Emit the "annotations" map.  Returns a json_gen_status; callers can wrap
   the call with GEN_OR_FAIL.  */
static int
gen_annotations (json_gen_ctx *gen, json_map_string_string *annotations)
{
  size_t i;
  int r;

  GEN_KEY (gen, "annotations");
  GEN_OR_FAIL (json_gen_map_open (gen));

  for (i = 0; i < annotations->len; i++)
    {
      /* An annotation whose value is null in the document is parsed into a
         NULL, which cannot be emitted as a JSON string; leave it out.  */
      if (annotations->keys[i] == NULL || annotations->values[i] == NULL)
        continue;

      GEN_STR (gen, annotations->keys[i]);
      GEN_STR (gen, annotations->values[i]);
    }

  return json_gen_map_close (gen);

gen_error:
  return r;
}

static int
do_hooks (runtime_spec_schema_config_schema *def, pid_t pid, const char *id, bool keep_going, const char *cwd,
          const char *status, const char *name, hook **hooks, size_t hooks_len, int out_fd, int err_fd,
          bool can_ignore_chdir_errors, libcrun_error_t *err)
{
  size_t i, stdin_len;
  int r, ret;
  char *stdin = NULL;
  cleanup_free char *cwd_allocated = NULL;
  const char *rootfs = def->root ? def->root->path : "";
  cleanup_json_gen json_gen_ctx *gen = NULL;

  if (cwd == NULL)
    {
      cwd = cwd_allocated = getcwd (NULL, 0);
      if (cwd == NULL)
        OOM ();
    }

  if (! json_gen_init (&gen, NULL))
    return crun_make_error (err, 0, "json_gen_init failed");

  json_gen_config (gen, json_gen_beautify, 0);

  GEN_OR_FAIL (json_gen_map_open (gen));

  GEN_KEY (gen, "ociVersion");
  GEN_STR (gen, "1.0");

  GEN_KEY (gen, "id");
  GEN_STR (gen, id);

  GEN_KEY (gen, "pid");
  GEN_OR_FAIL (map_int (gen, pid));

  GEN_KEY (gen, "root");
  GEN_STR (gen, rootfs);

  GEN_KEY (gen, "bundle");
  GEN_STR (gen, cwd);

  GEN_KEY (gen, "status");
  GEN_STR (gen, status);

  if (def && def->annotations && def->annotations->len)
    GEN_OR_FAIL (gen_annotations (gen, def->annotations));

  GEN_OR_FAIL (json_gen_map_close (gen));

  GEN_OR_FAIL (json_gen_get_buf (gen, (const char **) &stdin, &stdin_len));

  ret = 0;

  bool error_created = false;
  for (i = 0; i < hooks_len; i++)
    {
      char **env = environ;

      if (hooks[i]->env)
        env = hooks[i]->env;

      /* Release the error from the previous iteration, if any.  */
      if (error_created)
        {
          crun_error_release (err);
          error_created = false;
        }

      ret = run_process_with_stdin_timeout_envp (hooks[i]->path, hooks[i]->args, cwd, hooks[i]->timeout, env,
                                                 stdin, stdin_len, out_fd, err_fd, can_ignore_chdir_errors, err);
      if (UNLIKELY (ret < 0))
        error_created = true;

      if (UNLIKELY (ret != 0))
        {
          if (keep_going)
            libcrun_warning ("error running %s hook #%zu: `%s` (exit code: %d)", name, i, hooks[i]->path, ret);
          else
            {
              libcrun_error (0, "error running %s hook #%zu: `%s` (exit code: %d)", name, i, hooks[i]->path, ret);
              break;
            }
        }
    }

  return ret;

gen_error:
  return json_gen_error_to_crun_error (r, err);
}

static int
get_json_gen_result (json_gen_ctx *gen, char **out, size_t *out_len)
{
  const char *buf = NULL;
  size_t buf_len = 0;
  int r;

  r = json_gen_get_buf (gen, &buf, &buf_len);
  if (UNLIKELY (r != json_gen_status_ok))
    return r;

  *out_len = buf_len;

  *out = xmalloc (buf_len + 1);
  memcpy (*out, buf, buf_len);
  (*out)[buf_len] = '\0';

  return json_gen_status_ok;
}

static int
get_seccomp_receiver_fd_payload (libcrun_container_t *container, const char *status, pid_t own_pid,
                                 char **seccomp_fd_payload, size_t *seccomp_fd_payload_len, libcrun_error_t *err)
{
  int r;
  json_gen_ctx *gen = NULL;
  runtime_spec_schema_config_schema *def = container->container_def;
  const char *const OCI_VERSION = "0.2.0";

  if (! json_gen_init (&gen, NULL))
    return crun_make_error (err, 0, "json_gen_init failed");

  json_gen_config (gen, json_gen_beautify, 1);

  GEN_OR_FAIL (json_gen_map_open (gen));

  GEN_KEY (gen, "ociVersion");
  GEN_STR (gen, OCI_VERSION);

  GEN_KEY (gen, "fds");
  GEN_OR_FAIL (json_gen_array_open (gen));

  GEN_KEY (gen, "seccompFd");
  GEN_OR_FAIL (json_gen_array_close (gen));

  GEN_KEY (gen, "pid");
  GEN_OR_FAIL (map_int (gen, own_pid));

  if (def && def->linux && def->linux->seccomp)
    {
      const char *metadata = def->linux->seccomp->listener_metadata;

      if (metadata)
        {
          GEN_KEY (gen, "metadata");
          GEN_STR (gen, metadata);
        }
    }

  /* State.  */
  GEN_KEY (gen, "state");
  GEN_OR_FAIL (json_gen_map_open (gen));

  GEN_KEY (gen, "ociVersion");
  GEN_STR (gen, OCI_VERSION);

  if (container->context && container->context->id)
    {
      GEN_KEY (gen, "id");
      GEN_STR (gen, container->context->id);
    }

  GEN_KEY (gen, "status");
  GEN_STR (gen, status);

  GEN_KEY (gen, "pid");
  GEN_OR_FAIL (map_int (gen, own_pid));

  if (container->context && container->context->bundle)
    {
      GEN_KEY (gen, "bundle");
      GEN_STR (gen, container->context->bundle);
    }

  if (def->annotations && def->annotations->len)
    GEN_OR_FAIL (gen_annotations (gen, def->annotations));

  GEN_OR_FAIL (json_gen_map_close (gen));
  /* End state.  */

  GEN_OR_FAIL (json_gen_map_close (gen));

  r = get_json_gen_result (gen, seccomp_fd_payload, seccomp_fd_payload_len);

gen_error:
  json_gen_free (gen);

  return json_gen_error_to_crun_error (r, err);
}

static int
send_sync_cb (void *data, libcrun_error_t *err)
{
  int sync_socket_fd = *((int *) data);
  int ret;

  /* sync 2.  */
  ret = sync_socket_send_sync (sync_socket_fd, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* sync 3.  */
  return sync_socket_wait_sync (NULL, sync_socket_fd, false, err);
}

static int
maybe_chown_std_streams (uid_t container_uid, gid_t container_gid, libcrun_error_t *err)
{
  int ret, i;

  for (i = 0; i < 3; i++)
    {
      if (! isatty (i))
        {
          struct stat statbuf;
          ret = fstat (i, &statbuf);
          if (UNLIKELY (ret < 0))
            {
              if (errno == EBADF)
                continue;
              return crun_make_error (err, errno, "fstat fd `%d`", i);
            }

          /* Skip chown for device files */
          if (S_ISCHR (statbuf.st_mode) || S_ISBLK (statbuf.st_mode))
            continue;

          ret = fchown (i, container_uid, container_gid);
          if (UNLIKELY (ret < 0))
            {
              /* EINVAL means the user is not mapped in the current userns.
                 Ignore EPERM and EROFS as well as there is no reason to fail
                 so early, and let the container payload deal with it.
                 EBADF means fd is closed.
              */
              if (errno == EINVAL || errno == EPERM || errno == EROFS || errno == EBADF)
                continue;

              return crun_make_error (err, errno, "fchown std stream `%i`", i);
            }
        }
    }
  return 0;
}

int
libcrun_container_notify_handler (struct container_entrypoint_s *args,
                                  enum handler_configure_phase phase,
                                  libcrun_container_t *container, const char *rootfs,
                                  libcrun_error_t *err)
{
  struct custom_handler_s *h;

  if (args->custom_handler == NULL)
    return 0;

  h = args->custom_handler->vtable;
  if (h == NULL || h->configure_container == NULL)
    return 0;

  return h->configure_container (args->custom_handler->cookie, phase,
                                 args->context, container,
                                 rootfs, err);
}

/* Resolve and normalize the container rootfs path.  */
static int
resolve_rootfs_path (libcrun_container_t *container, char **rootfs, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  if (def->root && def->root->path)
    {
      *rootfs = realpath (def->root->path, NULL);
      if (UNLIKELY (*rootfs == NULL))
        {
          int saved_errno = errno;

          /* If realpath failed for any reason, try the relative directory.  */
          if (def->root->path[0] == '/')
            {
              cleanup_free char *cwd = NULL;
              libcrun_error_t tmp_err = NULL;
              ssize_t len;
              int proc_fd;

              proc_fd = libcrun_get_cached_proc_fd (container, &tmp_err);
              if (LIKELY (proc_fd >= 0))
                {
                  len = safe_readlinkat (proc_fd, "self/cwd", &cwd, 0, &tmp_err);
                  if (LIKELY (len > 0))
                    {
                      /* If the rootfs is under the current working directory, just use its relative path.  */
                      if (has_dir_prefix (def->root->path, cwd))
                        {
                          const char *it = consume_slashes (def->root->path + len);
                          if (LIKELY (*it))
                            {
                              int ret = faccessat (AT_FDCWD, it, F_OK, 0);
                              if (LIKELY (ret == 0))
                                *rootfs = xstrdup (it);
                            }
                        }
                    }
                }
              crun_error_release (&tmp_err);
            }

          if (*rootfs == NULL)
            {
              if (saved_errno == ENOENT)
                return crun_make_error (err, ENOENT, "the rootfs path `%s` does not exist", def->root->path);

              *rootfs = xstrdup (def->root->path);
            }
        }
    }
  return 0;
}

/* Initialize the environment variables.  */
static int
setup_environment (runtime_spec_schema_config_schema *def, uid_t container_uid, libcrun_error_t *err)
{
  int ret;

  if (clearenv ())
    return crun_make_error (err, errno, "clearenv");

  if (def->process)
    {
      size_t i;

      for (i = 0; i < def->process->env_len; i++)
        {
          /* A null element of the array of variables is parsed into a NULL,
             which putenv(3) cannot be handed.  */
          if (def->process->env[i] == NULL)
            return crun_make_error (err, EINVAL, "environment variable is not specified");

          if (putenv (def->process->env[i]) < 0)
            return crun_make_error (err, errno, "putenv `%s`", def->process->env[i]);
        }
    }

  if (getenv ("HOME") == NULL)
    {
      ret = set_home_env (container_uid);
      if (UNLIKELY (ret < 0))
        {
          libcrun_warning ("cannot detect HOME environment variable, setting default");
          if (UNLIKELY (setenv ("HOME", "/", 1) < 0))
            return crun_make_error (err, errno, "setenv HOME");
        }
    }

  return 0;
}

/* Configure terminal and console for interactive containers.  */
static int
setup_terminal (struct container_entrypoint_s *entrypoint_args, libcrun_container_t *container,
                int console_socket, int console_socketpair, int has_terminal, libcrun_error_t *err)
{
  cleanup_close int terminal_fd = -1;
  int ret;

  if (! has_terminal)
    return 0;

  fflush (stderr);

  if (console_socket >= 0 || (entrypoint_args->has_terminal_socket_pair && console_socketpair >= 0))
    {
      terminal_fd = libcrun_set_terminal (container, err);
      if (UNLIKELY (terminal_fd < 0))
        return terminal_fd;
    }

  if (console_socket >= 0)
    {
      ret = send_fd_to_socket (console_socket, terminal_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else if (entrypoint_args->has_terminal_socket_pair && console_socketpair >= 0)
    {
      ret = send_fd_to_socket (console_socketpair, terminal_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

/* Resolve and validate the container's executable path.  */
static int
setup_executable_path (struct container_entrypoint_s *entrypoint_args, runtime_spec_schema_config_schema *def,
                       char **exec_path, libcrun_error_t *err)
{
  int ret;

  if (def->process && def->process->args)
    {
      ret = find_executable (exec_path, def->process->args[0], def->process->cwd, err);
      if (UNLIKELY (ret < 0))
        {
          if (entrypoint_args->custom_handler == NULL && crun_error_get_errno (err) == ENOENT)
            return ret;

          /* If it fails for any other reason, ignore the failure.  We'll try again the lookup
             once the process switched to the use that runs in the container.  This might be necessary
             when opening a file that is on a network file system like NFS, where CAP_DAC_OVERRIDE
             is not honored.  */
          crun_error_release (err);
        }
    }

  return 0;
}

/* Apply security settings for the container process.  */
static int
apply_security_settings (struct container_entrypoint_s *entrypoint_args, runtime_spec_schema_config_schema *def,
                         libcrun_container_t *container, pid_t own_pid, libcrun_error_t *err)
{
  int ret;
  runtime_spec_schema_config_schema_process_capabilities *capabilities;
  int no_new_privs;

  if (def->process && ! def->process->no_new_privileges)
    {
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      cleanup_free char *seccomp_fd_payload = NULL;
      size_t seccomp_fd_payload_len = 0;

      if (def->linux && def->linux->seccomp)
        {
          seccomp_flags = def->linux->seccomp->flags;
          seccomp_flags_len = def->linux->seccomp->flags_len;
        }

      if (entrypoint_args->seccomp_receiver_fd >= 0)
        {
          ret = get_seccomp_receiver_fd_payload (container, "creating", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = libcrun_apply_seccomp (entrypoint_args->seccomp_fd, entrypoint_args->seccomp_receiver_fd,
                                   seccomp_fd_payload, seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      close_and_reset (&entrypoint_args->seccomp_fd);
      close_and_reset (&entrypoint_args->seccomp_receiver_fd);
    }

  capabilities = def->process ? def->process->capabilities : NULL;
  no_new_privs = def->process ? def->process->no_new_privileges : 1;
  ret = libcrun_set_caps (capabilities, container->container_uid, container->container_gid, no_new_privs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
container_init_setup (void *args, pid_t own_pid, char *notify_socket,
                      int sync_socket, char **exec_path, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  libcrun_container_t *container = entrypoint_args->container;
  bool chdir_done = false;
  int ret;
  int has_terminal;
  cleanup_close int console_socket = -1;
  cleanup_close int console_socketpair = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_free char *rootfs = NULL;

  ret = initialize_security (container, def->process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_configure_network (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = resolve_rootfs_path (container, &rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Configure terminal socket pair for container communication.  */
  if (entrypoint_args->terminal_socketpair[0] >= 0)
    {
      close_and_reset (&entrypoint_args->terminal_socketpair[0]);
      console_socketpair = entrypoint_args->terminal_socketpair[1];
    }

  /* sync 1.  */
  ret = sync_socket_wait_sync (NULL, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  has_terminal = container->container_def->process && container->container_def->process->terminal;
  if (has_terminal && entrypoint_args->context->console_socket)
    console_socket = entrypoint_args->console_socket_fd;

  ret = libcrun_set_sysctl (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_container_notify_handler (entrypoint_args, HANDLER_CONFIGURE_BEFORE_MOUNTS, container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_do_pivot_root (container, entrypoint_args->context->no_pivot, &rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* sync 2 and 3 are sent as part of libcrun_set_mounts.  */
  ret = libcrun_set_mounts (entrypoint_args, container, rootfs, send_sync_cb, &sync_socket, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* The createContainer hooks MUST run after the mounts are set up but before
     the pivot_root.  When these hooks are present can_use_open_tree_namespace()
     forces the deferred-pivot path, so the actual pivot happens later in
     libcrun_finalize_mounts().  */
  if (def->hooks && def->hooks->create_container_len)
    {
      libcrun_error_t tmp_err = NULL;
      int in_userns = check_running_in_user_namespace (&tmp_err);
      if (tmp_err)
        crun_error_release (&tmp_err);
      ret = do_hooks (def, 0, container->context->id, false, NULL, "created", "createContainer", (hook **) def->hooks->create_container,
                      def->hooks->create_container_len, entrypoint_args->hooks_out_fd, entrypoint_args->hooks_err_fd,
                      in_userns > 0, err);
      if (UNLIKELY (ret != 0))
        return ret;
    }

  ret = libcrun_finalize_mounts (entrypoint_args, container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process)
    {
      ret = libcrun_set_selinux_label (container, def->process, false, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcrun_set_apparmor_profile (container, def->process, false, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = mark_or_close_fds_ge_than (container, entrypoint_args->context->preserve_fds + 3, false, err);
  if (UNLIKELY (ret < 0))
    crun_error_write_warning_and_release (entrypoint_args->context->output_handler_arg, &err);

  ret = libcrun_reopen_dev_null (err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = maybe_chown_std_streams (container->container_uid, container->container_gid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = setup_environment (def, container->container_uid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Set primary process to 1 explicitly if nothing is configured and LISTEN_FD is not set.  */
  if (entrypoint_args->context->listen_fds > 0 && getenv ("LISTEN_PID") == NULL)
    {
      libcrun_warning ("setting LISTEN_PID=1 since no previous configuration was found");
      if (UNLIKELY (setenv ("LISTEN_PID", "1", 1) < 0))
        return crun_make_error (err, errno, "setenv LISTENPID");
    }

  /* Attempt to chdir immediately here, before doing the setresuid.  If we fail here, let's
     try again later once the process switched to the user that runs in the container.  */
  if (def->process && def->process->cwd)
    {
      ret = libcrun_safe_chdir (def->process->cwd, err);
      if (LIKELY (ret == 0))
        chdir_done = true;
      else
        crun_error_release (err);
    }

  ret = setsid ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setsid");

  ret = setup_terminal (entrypoint_args, container, console_socket, console_socketpair, has_terminal, err);
  if (UNLIKELY (ret < 0))
    return ret;

  close_and_reset (&console_socket);
  close_and_reset (&console_socketpair);

  ret = setup_executable_path (entrypoint_args, def, exec_path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_hostname (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_domainname (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->container_def->linux && container->container_def->linux->personality)
    {
      ret = libcrun_set_personality (container->container_def->linux->personality, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process && def->process->user)
    umask (def->process->user->umask_present ? def->process->user->umask : 0022);

  ret = apply_security_settings (entrypoint_args, def, container, own_pid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (def->process && def->process->args && *exec_path == NULL))
    {
      ret = find_executable (exec_path, def->process->args[0], def->process->cwd, err);
      if (UNLIKELY (ret < 0))
        {
          if (entrypoint_args->custom_handler == NULL || is_empty_string (def->process->args[0]))
            return ret;

          /* If a custom handler is used, pass argv0 as specified.  e.g. with wasm the file could miss the +x bit.  */
          crun_error_release (err);
          *exec_path = xstrdup (def->process->args[0]);
        }
    }

  /* The chdir was not already performed, so try again now after switching to the UID/GID in the container.  */
  if (! chdir_done && def->process && def->process->cwd)
    {
      ret = libcrun_safe_chdir (def->process->cwd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (notify_socket && putenv (notify_socket) < 0)
    return crun_make_error (err, errno, "putenv `%s`", notify_socket);

  return 0;
}

static int
open_hooks_output (libcrun_container_t *container, int *out_fd, int *err_fd, libcrun_error_t *err)
{
  const char *annotation;

  *err_fd = *out_fd = -1;

  libcrun_debug ("Opening hooks output");
  annotation = find_annotation (container, "run.oci.hooks.stdout");
  if (annotation)
    {
      libcrun_debug ("Found `run.oci.hooks.stdout` annotation");
      *out_fd = TEMP_FAILURE_RETRY (open (annotation, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0700));
      if (UNLIKELY (*out_fd < 0))
        return crun_make_error (err, errno, "open `%s`", annotation);
    }

  annotation = find_annotation (container, "run.oci.hooks.stderr");
  if (annotation)
    {
      libcrun_debug ("Found `run.oci.hooks.stderr` annotation");
      *err_fd = TEMP_FAILURE_RETRY (open (annotation, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0700));
      if (UNLIKELY (*err_fd < 0))
        return crun_make_error (err, errno, "open `%s`", annotation);
    }

  return 0;
}

static void
rewrite_argv (char **argv, int argc, const char *name, char **args, size_t args_len)
{
  cleanup_free char *decorated_name = NULL;
  size_t available_len = argv[argc - 1] - argv[0] + strlen (argv[argc - 1]) + 1;
  cleanup_free char *new_argv = NULL;
  size_t i, so_far = 0, needed = 0;

  needed = xasprintf (&decorated_name, "[libcrun:%s]", name) + 1;
  for (i = 0; i < args_len; i++)
    needed += strlen (args[i]) + 1;

  new_argv = xmalloc0 (needed + 1);
  strcpy (new_argv, decorated_name);
  so_far = strlen (decorated_name) + 1;

  if (available_len >= needed)
    {
      for (i = 0; i < args_len; i++)
        {
          strcpy (new_argv + so_far, args[i]);
          so_far += strlen (args[i]) + 1;
        }
    }

  if (so_far >= available_len)
    so_far = available_len - 1;

  memset (argv[0], 0, available_len);
  memcpy (argv[0], new_argv, so_far);
}

/* Entrypoint to the container.  */
static int
container_init (void *args, char *notify_socket, int sync_socket, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  int ret;
  runtime_spec_schema_config_schema *def = entrypoint_args->container->container_def;
  cleanup_free char *exec_path = NULL;
  __attribute__ ((unused)) cleanup_free char *notify_socket_cleanup = notify_socket;
  pid_t own_pid = 0;

  entrypoint_args->sync_socket = sync_socket;

  crun_set_output_handler (log_write_to_sync_socket, args);

  /* sync receive own pid.  */
  ret = TEMP_FAILURE_RETRY (read (sync_socket, &own_pid, sizeof (own_pid)));
  if (UNLIKELY (ret != sizeof (own_pid)))
    {
      if (ret >= 0)
        errno = 0;
      return crun_make_error (err, errno, "read from sync socket");
    }

  ret = container_init_setup (args, own_pid, notify_socket, sync_socket, &exec_path, err);
  if (UNLIKELY (ret < 0))
    {
      /* If it fails to write the error using the sync socket, then fallback
         to stderr.  */
      if (sync_socket_write_error (sync_socket, err) == 0)
        {
          crun_error_release (err);
          /* A return value of > 0 means to fail with an error without err being set so to avoid
             printing it twice.  */
          return 1;
        }
      return ret;
    }

  entrypoint_args->sync_socket = -1;

  ret = unblock_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* sync 4.  */
  ret = sync_socket_send_sync (sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  close_and_reset (&sync_socket);

  if (entrypoint_args->context->fifo_exec_wait_fd >= 0)
    {
      char buffer[1];
      fd_set read_set;
      cleanup_close int fd = entrypoint_args->context->fifo_exec_wait_fd;
      entrypoint_args->context->fifo_exec_wait_fd = -1;

      FD_ZERO (&read_set);
      FD_SET (fd, &read_set);
      do
        {
          ret = select (fd + 1, &read_set, NULL, NULL, NULL);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "select");

          ret = TEMP_FAILURE_RETRY (read (fd, buffer, sizeof (buffer)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read from the exec fifo");
      } while (ret == 0);

      close_and_reset (&entrypoint_args->context->fifo_exec_wait_fd);
    }

  crun_set_output_handler (log_write_to_stderr, NULL);

  if (def->process && def->process->no_new_privileges)
    {
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      cleanup_free char *seccomp_fd_payload = NULL;
      size_t seccomp_fd_payload_len = 0;

      if (def->linux && def->linux->seccomp)
        {
          seccomp_flags = def->linux->seccomp->flags;
          seccomp_flags_len = def->linux->seccomp->flags_len;
        }

      if (entrypoint_args->seccomp_receiver_fd >= 0)
        {
          ret = get_seccomp_receiver_fd_payload (entrypoint_args->container, "creating", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = libcrun_apply_seccomp (entrypoint_args->seccomp_fd, entrypoint_args->seccomp_receiver_fd,
                                   seccomp_fd_payload, seccomp_fd_payload_len, seccomp_flags,
                                   seccomp_flags_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      close_and_reset (&entrypoint_args->seccomp_fd);
      close_and_reset (&entrypoint_args->seccomp_receiver_fd);
    }

  if (UNLIKELY (def->process == NULL))
    return crun_make_error (err, 0, "block `process` not found");

  if (UNLIKELY (exec_path == NULL))
    return crun_make_error (err, 0, "executable path not specified");

  if (def->hooks && def->hooks->start_container_len)
    {
      libcrun_container_t *container = entrypoint_args->container;
      libcrun_error_t tmp_err = NULL;
      int in_userns = check_running_in_user_namespace (&tmp_err);
      if (tmp_err)
        crun_error_release (&tmp_err);

      ret = do_hooks (def, 0, container->context->id, false, NULL, "starting", "startContainer", (hook **) def->hooks->start_container,
                      def->hooks->start_container_len, entrypoint_args->hooks_out_fd, entrypoint_args->hooks_err_fd,
                      in_userns > 0, err);
      if (UNLIKELY (ret != 0))
        return ret;

      /* Seek stdout/stderr to the end.  If the hooks were using the same files,
         the container process overwrites what was previously written.  */
      (void) lseek (1, 0, SEEK_END);
      (void) lseek (2, 0, SEEK_END);
    }

  if (entrypoint_args->custom_handler)
    {
      /* Files marked with O_CLOEXEC are closed at execv time, so make sure they are closed now.
         This is a best effort operation, because the seccomp filter is already in place and it could
         stop some syscalls used by mark_or_close_fds_ge_than.
      */
      if (entrypoint_args->custom_handler->vtable->close_fds)
        {
          ret = entrypoint_args->custom_handler->vtable->close_fds (entrypoint_args->custom_handler->cookie,
                                                                    entrypoint_args->container,
                                                                    entrypoint_args->context->preserve_fds,
                                                                    err);
        }
      else
        {
          ret = mark_or_close_fds_ge_than (entrypoint_args->container, entrypoint_args->context->preserve_fds + 3, true, err);
        }
      if (UNLIKELY (ret < 0))
        crun_error_release (err);

      prctl (PR_SET_NAME, entrypoint_args->custom_handler->vtable->name);

      if (entrypoint_args->context->argv)
        {
          rewrite_argv (entrypoint_args->context->argv, entrypoint_args->context->argc,
                        entrypoint_args->custom_handler->vtable->name, def->process->args,
                        def->process->args_len);

          /* It is a quite destructive operation as we might be referencing data from the old
             argv, so make sure the context is not reused.  */
          entrypoint_args->context->argv = NULL;
          entrypoint_args->context = NULL;
        }

      ret = libcrun_set_selinux_label (entrypoint_args->container, def->process, true, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcrun_set_apparmor_profile (entrypoint_args->container, def->process, true, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = entrypoint_args->custom_handler->vtable->run_func (entrypoint_args->custom_handler->cookie,
                                                               entrypoint_args->container,
                                                               exec_path,
                                                               def->process->args);
      if (ret != 0)
        return crun_make_error (err, 0, "exec container process failed with handler as `%s`", entrypoint_args->custom_handler->vtable->name);

      return ret;
    }

  /* Attempt to close all the files that are not needed to prevent execv to have access to them.
     This is a best effort operation since the seccomp profile is already in place now and might block
     some of the syscalls needed by mark_or_close_fds_ge_than.  */
  ret = mark_or_close_fds_ge_than (entrypoint_args->container, entrypoint_args->context->preserve_fds + 3, true, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  TEMP_FAILURE_RETRY (execv (exec_path, def->process->args));

  if (errno == ENOENT)
    return crun_make_error (err, errno, "exec container process (missing dynamic library?) `%s`", exec_path);

  return crun_make_error (err, errno, "exec container process `%s`", exec_path);
}

static int
read_container_config_from_state (libcrun_container_t **container, const char *state_root, const char *id,
                                  libcrun_error_t *err)
{
  cleanup_free char *config_file = NULL;
  cleanup_free char *dir = NULL;
  int ret;

  *container = NULL;

  ret = libcrun_get_state_directory (&dir, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&config_file, err, dir, "config.json", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  *container = libcrun_container_load_from_file (config_file, err);
  if (*container == NULL)
    return -1;

  return 0;
}

static int
run_poststop_hooks (libcrun_context_t *context, libcrun_container_t *container, runtime_spec_schema_config_schema *def,
                    libcrun_container_status_t *status, const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container_cleanup = NULL;
  int ret;

  if (def == NULL)
    {
      if (container == NULL)
        {
          ret = read_container_config_from_state (&container_cleanup, state_root, id, err);
          if (UNLIKELY (ret < 0))
            return ret;
          container = container_cleanup;
        }

      def = container->container_def;
    }

  if (def->hooks && def->hooks->poststop_len)
    {
      cleanup_close int hooks_out_fd = -1;
      cleanup_close int hooks_err_fd = -1;

      if (container == NULL)
        {
          ret = read_container_config_from_state (&container_cleanup, state_root, id, err);
          if (UNLIKELY (ret < 0))
            return ret;
          container = container_cleanup;
        }

      ret = open_hooks_output (container, &hooks_out_fd, &hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_hooks (def, 0, id, true, status->bundle, "stopped", "poststop", (hook **) def->hooks->poststop,
                      def->hooks->poststop_len, hooks_out_fd, hooks_err_fd, false, err);
      if (UNLIKELY (ret != 0))
        {
          if (ret < 0)
            crun_error_write_warning_and_release (context->output_handler_arg, &err);
          else
            libcrun_error (0, "poststop hook failed with exit code: %d", ret);
        }
    }
  return 0;
}

static bool
has_new_pid_namespace (runtime_spec_schema_config_schema *def)
{
  size_t i;

  if (def->linux == NULL || def->linux->namespaces == NULL)
    return false;

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      if (strcmp (def->linux->namespaces[i]->type, "pid") == 0 && def->linux->namespaces[i]->path == NULL)
        return true;
    }
  return false;
}

static int
container_delete_internal (libcrun_context_t *context, runtime_spec_schema_config_schema *def,
                           const char *id, bool force, bool killall, libcrun_error_t *err)
{
  cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;
  cleanup_container_status libcrun_container_status_t status = {};
  cleanup_container libcrun_container_t *container = NULL;
  const char *state_root = context->state_root;
  int ret;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    {
      if (force && crun_error_get_errno (err) == ENOENT)
        {
          libcrun_error_t tmp_err = NULL;

          crun_error_release (err);
          libcrun_container_delete_status (state_root, id, &tmp_err);
          crun_error_release (&tmp_err);
          return 0;
        }
      crun_error_release (err);
      return libcrun_container_delete_status (state_root, id, err);
    }

  cgroup_status = libcrun_cgroup_make_status (&status);

  if (! force)
    {
      ret = libcrun_is_container_running (&status, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 1)
        {
          ret = libcrun_status_has_read_exec_fifo (state_root, id, err);
          if (UNLIKELY (ret < 0))
            return ret;
          if (ret == 0)
            return crun_make_error (err, 0, "the container `%s` is not in `created` or `stopped` state", id);

          /* If the container is in "created" state, then do the equivalent of delete --force.  */
          killall = force = true;
        }
    }

  if (def == NULL)
    {
      ret = read_container_config_from_state (&container, state_root, id, err);
      if (UNLIKELY (ret < 0))
        return ret;

      def = container->container_def;
    }

  if (killall && force)
    {
      /* If the container has a pid namespace, it is enough to kill the first
         process (pid=1 in the namespace).
      */
      if (has_new_pid_namespace (def))
        {
          ret = libcrun_kill_linux (&status, SIGKILL, err);
          if (UNLIKELY (ret < 0))
            {
              errno = crun_error_get_errno (err);

              /* pidfd_open returns EINVAL if the process is not a thread-group leader.
                 In our case it means the process already exited, so handle as ESRCH.  */
              if (errno != ESRCH && errno != EINVAL)
                return ret;

              crun_error_release (err);
            }
        }
      else if (status.cgroup_path)
        {
          ret = libcrun_cgroup_killall (cgroup_status, SIGKILL, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (def->linux && def->linux->intel_rdt)
    {
      ret = libcrun_destroy_intelrdt (id, def, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->output_handler_arg, &err);
    }

  if (status.cgroup_path)
    {
      ret = libcrun_cgroup_destroy (cgroup_status, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->output_handler_arg, &err);
    }

  ret = run_poststop_hooks (context, container, def, &status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    crun_error_write_warning_and_release (context->output_handler_arg, &err);

  return libcrun_container_delete_status (state_root, id, err);
}

int
libcrun_container_delete (libcrun_context_t *context, runtime_spec_schema_config_schema *def, const char *id,
                          bool force, libcrun_error_t *err)
{
  return container_delete_internal (context, def, id, force, true, err);
}

int
libcrun_container_kill (libcrun_context_t *context, const char *id, const char *signal, libcrun_error_t *err)
{
  int sig, ret;
  const char *state_root = context->state_root;
  cleanup_container_status libcrun_container_status_t status = {};

  sig = str2sig (signal);
  if (UNLIKELY (sig < 0))
    return crun_make_error (err, 0, "unknown signal `%s`", signal);

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_kill_linux (&status, sig, err);
}

int
libcrun_container_killall (libcrun_context_t *context, const char *id, const char *signal, libcrun_error_t *err)
{
  int sig, ret;
  const char *state_root = context->state_root;
  cleanup_container_status libcrun_container_status_t status = {};
  cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;

  sig = str2sig (signal);
  if (UNLIKELY (sig < 0))
    return crun_make_error (err, 0, "unknown signal `%s`", signal);

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  cgroup_status = libcrun_cgroup_make_status (&status);

  ret = libcrun_cgroup_killall (cgroup_status, sig, err);
  if (UNLIKELY (ret < 0))
    return ret;
  return 0;
}

static int
write_container_status (libcrun_container_t *container, libcrun_context_t *context,
                        pid_t pid, struct libcrun_cgroup_status *cgroup_status,
                        libcrun_error_t *err)
{
  cleanup_free char *cwd = getcwd (NULL, 0);
  if (UNLIKELY (cwd == NULL))
    libcrun_fail_with_error (errno, "getcwd failed");
  cleanup_free char *owner = get_user_name (geteuid ());
  char *external_descriptors = libcrun_get_external_descriptors (container);
  char *rootfs = container->container_def->root ? container->container_def->root->path : "";
  char created[35];

  libcrun_container_status_t status = {
    .pid = pid,
    .rootfs = rootfs,
    .bundle = cwd,
    .created = created,
    .owner = owner,
    .systemd_cgroup = context->systemd_cgroup,
    .detached = context->detach,
    .external_descriptors = external_descriptors,
    .cgroup_path = NULL,
    .scope = NULL,
  };

  get_current_timestamp (created, sizeof (created));

  if (cgroup_status)
    {
      int ret;

      ret = libcrun_cgroup_get_status (cgroup_status, &status, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (external_descriptors == NULL)
    return crun_make_error (err, 0, "invalid internal state.  No external descriptors found");
  return libcrun_write_container_status (context->state_root, context->id, &status, err);
}

static int
reap_subprocesses (pid_t main_process, int *main_process_exit, int *last_process, libcrun_error_t *err)
{
  *last_process = 0;
  while (1)
    {
      int status;
      int r = waitpid_ignore_stopped (-1, &status, WNOHANG);
      if (r < 0)
        {
          if (errno == EINTR)
            continue;
          if (errno == ECHILD)
            {
              *last_process = 1;
              return 0;
            }
          return crun_make_error (err, errno, "waitpid");
        }
      if (r == 0)
        break;
      if (r != main_process)
        continue;

      *main_process_exit = get_process_exit_status (status);
    }
  return 0;
}

static int
send_sd_notify (const char *ready_str, libcrun_error_t *err)
{
#ifdef HAVE_SYSTEMD
  int ret = sd_notify (0, ready_str);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "sd_notify");

#  if HAVE_SD_NOTIFY_BARRIER
  /* Hard-code a 30 seconds timeout.  Ignore errors.  */
  sd_notify_barrier (0, 30 * 1000000);
#  endif
#else
  (void) ready_str;
  (void) err;
#endif
  return 0;
}

static int
handle_notify_socket (int notify_socketfd, libcrun_error_t *err)
{
#ifdef HAVE_SYSTEMD
  int ret;
  char buf[256];
  const char *ready_str = "READY=1";

  ret = recvfrom (notify_socketfd, buf, sizeof (buf) - 1, 0, NULL, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "recvfrom notify socket");

  buf[ret] = '\0';
  if (strstr (buf, ready_str))
    {
      ret = send_sd_notify (ready_str, err);
      if (UNLIKELY (ret < 0))
        return ret;

      return 1;
    }
  return 0;
#else
  (void) notify_socketfd;
  (void) err;
  return 1;
#endif
}

struct wait_for_process_args
{
  pid_t pid;
  libcrun_context_t *context;
  int terminal_fd;
  int notify_socket;
  int *container_ready_fd;
  int seccomp_notify_fd;
  const char *seccomp_notify_plugins;
};

static int
write_pid_file (const char *pid_file, pid_t pid, libcrun_error_t *err)
{
  char buf[32];
  int buf_len = snprintf (buf, sizeof (buf), "%d", pid);
  if (UNLIKELY (buf_len >= (int) sizeof (buf)))
    return crun_make_error (err, 0, "internal error: static buffer too small");
  return write_file_at_with_flags (AT_FDCWD, O_CREAT | O_TRUNC, 0700, pid_file, buf, buf_len, err);
}

#define MAX_EVENTS 10

static int
wait_for_process (struct wait_for_process_args *args, libcrun_error_t *err)
{
  cleanup_channel_fd_pair struct channel_fd_pair *from_terminal = NULL;
  cleanup_channel_fd_pair struct channel_fd_pair *to_terminal = NULL;
  int ret, container_exit_code = 0, last_process;
  cleanup_close int terminal_fd_from = -1;
  cleanup_close int terminal_fd_to = -1;
  cleanup_close int epollfd = -1;
  cleanup_close int signalfd = -1;
  sigset_t mask;
  int in_fds[MAX_EVENTS];
  int in_fds_len = 0;
  int out_fds[MAX_EVENTS];
  int out_fds_len = 0;
  size_t i;

  cleanup_seccomp_notify_context struct seccomp_notify_context_s *seccomp_notify_ctx = NULL;

  container_exit_code = 0;

  if (args == NULL || args->context == NULL)
    return crun_make_error (err, 0, "internal error: context is empty");

  for (i = 0; i < MAX_EVENTS; i++)
    {
      in_fds[i] = -1;
      out_fds[i] = -1;
    }

  if (args->context->pid_file)
    {
      ret = write_pid_file (args->context->pid_file, args->pid, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Also exit if there is nothing more to wait for.  */
  if (args->context->detach && args->notify_socket < 0)
    return 0;

  if (args->container_ready_fd)
    {
      ret = 0;
      TEMP_FAILURE_RETRY (write (*args->container_ready_fd, &ret, sizeof (ret)));
      close_and_reset (args->container_ready_fd);
    }

  sigfillset (&mask);
  ret = sigprocmask (SIG_BLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");

  signalfd = create_signalfd (&mask, err);
  if (UNLIKELY (signalfd < 0))
    return signalfd;

  ret = reap_subprocesses (args->pid, &container_exit_code, &last_process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (last_process)
    return container_exit_code;

  if (args->seccomp_notify_fd >= 0)
    {
      cleanup_free char *state_root = NULL;
      cleanup_free char *oci_config_path = NULL;

      struct libcrun_load_seccomp_notify_conf_s conf;
      memset (&conf, 0, sizeof conf);

      ret = libcrun_get_state_directory (&state_root, args->context->state_root, args->context->id, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&oci_config_path, err, state_root, "config.json", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      conf.runtime_root_path = state_root;
      conf.name = args->context->id;
      conf.bundle_path = args->context->bundle;
      conf.oci_config_path = oci_config_path;

      ret = set_blocking_fd (args->seccomp_notify_fd, false, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcrun_load_seccomp_notify_plugins (&seccomp_notify_ctx,
                                                 args->seccomp_notify_plugins,
                                                 &conf, err);
      if (UNLIKELY (ret < 0))
        return ret;

      in_fds[in_fds_len++] = args->seccomp_notify_fd;
    }

  if (args->terminal_fd >= 0)
    {
      /* The terminal_fd is dup()ed so that it can be registered with
         epoll multiple times using different masks.  */
      terminal_fd_from = dup (args->terminal_fd);
      if (UNLIKELY (terminal_fd_from < 0))
        return crun_make_error (err, errno, "dup terminal fd");
      terminal_fd_to = dup (args->terminal_fd);
      if (UNLIKELY (terminal_fd_to < 0))
        return crun_make_error (err, errno, "dup terminal fd");

      int i, non_blocking_fds[] = { terminal_fd_from, terminal_fd_to, 0, 1, -1 };
      for (i = 0; non_blocking_fds[i] >= 0; i++)
        {
          ret = set_blocking_fd (non_blocking_fds[i], false, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      from_terminal = channel_fd_pair_new (terminal_fd_from, 1, BUFSIZ);
      to_terminal = channel_fd_pair_new (0, terminal_fd_to, BUFSIZ);
    }

  in_fds[in_fds_len++] = signalfd;
  if (args->notify_socket >= 0)
    in_fds[in_fds_len++] = args->notify_socket;
  if (args->terminal_fd >= 0)
    {
      in_fds[in_fds_len++] = 0;
      out_fds[out_fds_len++] = terminal_fd_to;

      in_fds[in_fds_len++] = terminal_fd_from;
      out_fds[out_fds_len++] = 1;
    }

  epollfd = epoll_helper (in_fds, NULL, out_fds, NULL, err);
  if (UNLIKELY (epollfd < 0))
    return epollfd;

  while (1)
    {
      struct epoll_event events[MAX_EVENTS];
      struct signalfd_siginfo si;
      struct winsize ws;
      int i, nr_events;
      ssize_t res;

      nr_events = TEMP_FAILURE_RETRY (epoll_wait (epollfd, events, MAX_EVENTS, -1));
      if (UNLIKELY (nr_events < 0))
        return crun_make_error (err, errno, "epoll_wait");

      for (i = 0; i < nr_events; i++)
        {
          if (events[i].data.fd == 0 || events[i].data.fd == terminal_fd_to)
            {
              ret = channel_fd_pair_process (to_terminal, epollfd, err);
              if (UNLIKELY (ret < 0))
                return crun_error_wrap (err, "copy to terminal fd");
            }
          else if (events[i].data.fd == 1 || events[i].data.fd == terminal_fd_from)
            {
              ret = channel_fd_pair_process (from_terminal, epollfd, err);
              if (UNLIKELY (ret < 0))
                return crun_error_wrap (err, "copy from terminal fd");
            }
          else if (events[i].data.fd == args->seccomp_notify_fd)
            {
              ret = libcrun_seccomp_notify_plugins (seccomp_notify_ctx,
                                                    args->seccomp_notify_fd, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          else if (events[i].data.fd == args->notify_socket)
            {
              ret = handle_notify_socket (args->notify_socket, err);
              if (UNLIKELY (ret < 0))
                return ret;
              if (ret && args->context->detach)
                return 0;
            }
          else if (events[i].data.fd == signalfd)
            {
              res = TEMP_FAILURE_RETRY (read (signalfd, &si, sizeof (si)));
              if (UNLIKELY (res < 0))
                return crun_make_error (err, errno, "read from signalfd");
              if (si.ssi_signo == SIGCHLD)
                {
                  ret = reap_subprocesses (args->pid, &container_exit_code,
                                           &last_process, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (last_process)
                    return container_exit_code;
                }
              else if (si.ssi_signo == SIGWINCH)
                {
                  /* Ignore the signal if the terminal is not available.  */
                  if (args->terminal_fd > 0)
                    {
                      ret = ioctl (0, TIOCGWINSZ, &ws);
                      if (UNLIKELY (ret < 0))
                        return crun_make_error (err, errno, "ioctl TIOCGWINSZ copy terminal size from stdin");

                      ret = ioctl (args->terminal_fd, TIOCSWINSZ, &ws);
                      if (UNLIKELY (ret < 0))
                        return crun_make_error (err, errno, "ioctl TIOCSWINSZ copy terminal size to pty");
                    }
                }
              else
                {
                  /* Send any other signal to the child process.  */
                  ret = kill (args->pid, si.ssi_signo);
                }
            }
          else
            {
              return crun_make_error (err, 0, "internal error: unknown fd from epoll_wait");
            }
        }
    }

  return 0;
}

static void
flush_fd_to_err (libcrun_context_t *context, int terminal_fd)
{
  char buf[256];
  int flags;

  if (terminal_fd < 0 || stderr == NULL)
    return;

  flags = fcntl (terminal_fd, F_GETFL, 0);
  if (flags == -1)
    return;
  if (fcntl (terminal_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return;

  for (;;)
    {
      int ret = TEMP_FAILURE_RETRY (read (terminal_fd, buf, sizeof (buf) - 1));
      if (ret <= 0)
        break;
      buf[ret] = '\0';
      if (context->output_handler)
        context->output_handler (0, buf, LIBCRUN_VERBOSITY_ERROR, context->output_handler_arg);
    }
  (void) fcntl (terminal_fd, F_SETFL, flags);
  fflush (stderr);
  fsync (1);
  fsync (2);
}

static int
cleanup_watch (libcrun_context_t *context, runtime_spec_schema_config_schema *def,
               struct libcrun_cgroup_status *cgroup_status, pid_t init_pid, int sync_socket,
               int terminal_fd, libcrun_error_t *err)
{
  const char *oom_message = NULL;
  libcrun_error_t tmp_err = NULL;
  int ret;

  if (init_pid)
    {
      /* Try to detect whether the cgroup has a OOM.  */
      if (cgroup_status)
        {
          int has_oom;

          has_oom = libcrun_cgroup_has_oom (cgroup_status, &tmp_err);
          if (has_oom > 0)
            oom_message = "OOM: the memory limit could be too low";
          else if (has_oom < 0)
            {
              /* If the detection has failed for any reason, e.g. the cgroup was
                 already deleted by the time it was checked, just ignore the
                 failure.  */
              crun_error_release (&tmp_err);
            }
        }
      /* If the OOM wasn't detected, look into the static configuration.  */
      if (oom_message == NULL && is_memory_limit_too_low (def))
        oom_message = "the memory limit could be too low";

      kill (init_pid, SIGKILL);
      waitpid_ignore_stopped (init_pid, NULL, 0);
    }

  ret = sync_socket_wait_sync (context, sync_socket, true, &tmp_err);
  if (UNLIKELY (ret < 0))
    {
      crun_error_release (err);
      *err = tmp_err;
    }

  if (terminal_fd >= 0)
    flush_fd_to_err (context, terminal_fd);

  if (oom_message)
    return crun_error_wrap (err, "%s", oom_message);

  return -1;
}

/* Find the uid:gid that is mapped to root inside the container user namespace.  */
void
get_root_in_the_userns (runtime_spec_schema_config_schema *def, uid_t host_uid, gid_t host_gid, uid_t *uid,
                        gid_t *gid)
{
  *uid = -1;
  *gid = -1;

  /* Not root in the namespace.  */
  if (host_uid)
    return;

  if (def->linux && def->linux->uid_mappings)
    {
      size_t i;

      for (i = 0; i < def->linux->uid_mappings_len; i++)
        if (def->linux->uid_mappings[i]->container_id == 0)
          {
            *uid = def->linux->uid_mappings[i]->host_id;
            break;
          }
    }
  if (def->linux && def->linux->gid_mappings)
    {
      size_t i;

      for (i = 0; i < def->linux->gid_mappings_len; i++)
        if (def->linux->gid_mappings[i]->container_id == 0)
          {
            *gid = def->linux->gid_mappings[i]->host_id;
            break;
          }
    }

  /* If the uid and the gid are not changed, do not attempt any chown.  */
  if (*uid == host_uid && *gid == host_gid)
    *uid = *gid = -1;
}

static int
get_seccomp_receiver_fd (libcrun_container_t *container, int *fd, int *self_receiver_fd, const char **plugins,
                         libcrun_error_t *err)
{
  const char *tmp;
  runtime_spec_schema_config_schema *def = container->container_def;

  *fd = -1;
  *self_receiver_fd = -1;

  tmp = find_annotation (container, "run.oci.seccomp.plugins");
  if (tmp)
    {
      int fds[2];
      int ret;

      ret = create_socket_pair (fds, err);
      if (UNLIKELY (ret < 0))
        return crun_error_wrap (err, "create socket pair");

      *fd = fds[0];
      *self_receiver_fd = fds[1];
      *plugins = tmp;
      return 0;
    }

  if (def && def->linux && def->linux->seccomp && def->linux->seccomp->listener_path)
    tmp = def->linux->seccomp->listener_path;
  else
    tmp = find_annotation (container, "run.oci.seccomp.receiver");
  if (tmp == NULL)
    tmp = getenv ("RUN_OCI_SECCOMP_RECEIVER");
  if (tmp)
    {
      if (tmp[0] != '/')
        return crun_make_error (err, 0, "the seccomp receiver `%s` is not an absolute path", tmp);

      *fd = open_unix_domain_client_socket (tmp, 0, err);
      if (UNLIKELY (*fd < 0))
        return crun_error_wrap (err, "open seccomp receiver");
    }

  return 0;
}

static bool
has_seccomp_receiver (libcrun_container_t *container)
{
  runtime_spec_schema_config_schema *def = container->container_def;

  if (def && def->linux && def->linux->seccomp && def->linux->seccomp->listener_path)
    return true;

  if (find_annotation (container, "run.oci.seccomp.receiver") != NULL || getenv ("RUN_OCI_SECCOMP_RECEIVER") != NULL)
    return true;

  return false;
}

static int
setup_container_hooks_output (libcrun_container_t *container, runtime_spec_schema_config_schema *def,
                              struct container_entrypoint_s *container_args, int *hooks_out_fd,
                              int *hooks_err_fd, libcrun_error_t *err)
{
  int ret;

  if (def->hooks
      && (def->hooks->prestart_len || def->hooks->poststart_len || def->hooks->create_runtime_len
          || def->hooks->create_container_len || def->hooks->start_container_len))
    {
      ret = open_hooks_output (container, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
      container_args->hooks_out_fd = *hooks_out_fd;
      container_args->hooks_err_fd = *hooks_err_fd;
    }
  return 0;
}

static int
setup_container_keyring (libcrun_container_t *container, libcrun_context_t *context, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;

  if (! context->no_new_keyring)
    {
      const char *label = NULL;

      libcrun_debug ("Creating new keyring");

      if (def->process)
        {
          label = def->process->selinux_label;
          if (label)
            libcrun_debug ("Using SELinux process label: `%s`", label);
        }

      ret = libcrun_create_keyring (container, container->context->id, label, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
setup_terminal_socket_pair (libcrun_container_t *container, libcrun_context_t *context,
                            struct container_entrypoint_s *container_args, int *socket_pair_0,
                            int *socket_pair_1, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  int detach = context->detach;

  if (def->process && def->process->terminal && ! detach && context->console_socket == NULL)
    {
      libcrun_debug ("Creating terminal socket pair");
      container_args->has_terminal_socket_pair = 1;
      ret = create_socket_pair (container_args->terminal_socketpair, err);
      if (UNLIKELY (ret < 0))
        return crun_error_wrap (err, "create terminal socket");

      *socket_pair_0 = container_args->terminal_socketpair[0];
      *socket_pair_1 = container_args->terminal_socketpair[1];
    }
  return 0;
}

static int
setup_seccomp (libcrun_container_t *container, const char *seccomp_bpf_data,
               struct libcrun_seccomp_gen_ctx_s *seccomp_gen_ctx, int *seccomp_fd, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;

  if (find_annotation (container, "run.oci.seccomp.plugins") != NULL && has_seccomp_receiver (container))
    {
      return crun_make_error (err, 0, "seccomp plugins and seccomp receivers cannot be declared at the same time");
    }

  if (def->linux && (def->linux->seccomp || seccomp_bpf_data))
    {
      unsigned int seccomp_gen_options = 0;
      const char *annotation;

      libcrun_debug ("Initializing seccomp");
      annotation = find_annotation (container, "run.oci.seccomp_fail_unknown_syscall");
      if (annotation && strcmp (annotation, "0") != 0)
        seccomp_gen_options = LIBCRUN_SECCOMP_FAIL_UNKNOWN_SYSCALL;

      if (seccomp_bpf_data)
        seccomp_gen_options |= LIBCRUN_SECCOMP_SKIP_CACHE;

      libcrun_seccomp_gen_ctx_init (seccomp_gen_ctx, container, true, seccomp_gen_options);

      ret = libcrun_open_seccomp_bpf (seccomp_gen_ctx, seccomp_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
setup_console_socket (libcrun_context_t *context, runtime_spec_schema_config_schema *def,
                      struct container_entrypoint_s *container_args, int *console_socket_fd,
                      libcrun_error_t *err)
{
  if (context->console_socket && def->process && def->process->terminal)
    {
      *console_socket_fd = open_unix_domain_client_socket (context->console_socket, 0, err);
      if (UNLIKELY (*console_socket_fd < 0))
        return crun_error_wrap (err, "open console socket");
      container_args->console_socket_fd = *console_socket_fd;
    }
  return 0;
}

static int
setup_cgroup_manager (libcrun_context_t *context, libcrun_container_t *container,
                      struct libcrun_cgroup_args *cg, int *cgroup_dirfd,
                      struct libcrun_dirfd_s *cgroup_dirfd_s, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int cgroup_manager;
  uid_t root_uid = -1;
  gid_t root_gid = -1;
  int ret;

  cgroup_manager = CGROUP_MANAGER_CGROUPFS;
  if (context->systemd_cgroup)
    {
      libcrun_debug ("Using systemd cgroup manager");
      cgroup_manager = CGROUP_MANAGER_SYSTEMD;
    }
  else if (context->force_no_cgroup)
    {
      libcrun_debug ("Disabling cgroup manager");
      cgroup_manager = CGROUP_MANAGER_DISABLED;
    }
  else
    libcrun_debug ("Using cgroupfs cgroup manager");

  /* If we are root (either on the host or in a namespace), then chown the cgroup to root
     in the container user namespace.  */
  get_root_in_the_userns (def, container->host_uid, container->host_gid, &root_uid, &root_gid);
  libcrun_debug ("Using container host UID `%d` and GID `%d`", container->host_uid, container->host_gid);

  memset (cg, 0, sizeof (*cg));

  cg->cgroup_path = def->linux ? def->linux->cgroups_path : "";
  cg->manager = cgroup_manager;
  cg->id = context->id;
  cg->resources = def->linux ? def->linux->resources : NULL;
  cg->annotations = container->annotations;
  cg->root_uid = root_uid;
  cg->root_gid = root_gid;
  cg->state_root = context->state_root;
  cg->container = container;

  ret = libcrun_cgroup_preenter (cg, cgroup_dirfd, err);
  if (UNLIKELY (ret < 0))
    return ret;

  cgroup_dirfd_s->dirfd = cgroup_dirfd;
  cgroup_dirfd_s->joined = false;

  return 0;
}

static int
set_scheduler (pid_t pid, runtime_spec_schema_config_schema *def, libcrun_error_t *err)
{
  int ret;

  ret = libcrun_set_scheduler (pid, def->process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_reset_cpu_affinity_mask (pid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_io_priority (pid, def->process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
seccomp_generation (int seccomp_fd, const char *seccomp_bpf_data,
                    struct libcrun_seccomp_gen_ctx_s *seccomp_gen_ctx, libcrun_error_t *err)
{
  int ret;

  if (seccomp_fd >= 0)
    {
      if (seccomp_bpf_data != NULL)
        {
          ret = libcrun_copy_seccomp (seccomp_gen_ctx, seccomp_bpf_data, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = libcrun_generate_seccomp (seccomp_gen_ctx, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  return 0;
}

static int
terminal_setup (runtime_spec_schema_config_schema *def, libcrun_context_t *context,
                int socket_pair_0, int *terminal_fd, void **orig_terminal, libcrun_error_t *err)
{
  int ret;
  int detach = context->detach;

  if (def->process && def->process->terminal && ! detach && context->console_socket == NULL)
    {
      libcrun_debug ("Receiving console socket fd");
      *terminal_fd = receive_fd_from_socket (socket_pair_0, err);
      if (UNLIKELY (*terminal_fd < 0))
        return -1;

      ret = libcrun_set_raw (0, orig_terminal, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
libcrun_container_run_internal (libcrun_container_t *container, libcrun_context_t *context,
                                int *container_ready_fd, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  pid_t pid;
  int detach = context->detach;
  cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;
  cleanup_close int terminal_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_close int sync_socket = -1;
  cleanup_close int notify_socket = -1;
  cleanup_close int socket_pair_0 = -1;
  cleanup_close int socket_pair_1 = -1;
  cleanup_close int seccomp_fd = -1;
  cleanup_close int console_socket_fd = -1;
  cleanup_close int hooks_out_fd = -1;
  cleanup_close int hooks_err_fd = -1;
  cleanup_close int own_seccomp_receiver_fd = -1;
  cleanup_close int seccomp_notify_fd = -1;
  const char *seccomp_notify_plugins = NULL;
  struct libcrun_cgroup_args cg;
  struct container_entrypoint_s container_args = {
    .container = container,
    .context = context,
    .terminal_socketpair = { -1, -1 },
    .console_socket_fd = -1,
    .hooks_out_fd = -1,
    .hooks_err_fd = -1,
    .seccomp_receiver_fd = -1,
    .custom_handler = NULL,
  };
  cleanup_close int cgroup_dirfd = -1;
  struct libcrun_dirfd_s cgroup_dirfd_s;
  struct libcrun_seccomp_gen_ctx_s seccomp_gen_ctx;
  const char *seccomp_bpf_data = find_annotation (container, "run.oci.seccomp_bpf_data");
  int cgroup_mode;

  if (! context->force_no_cgroup)
    {
      cgroup_mode = libcrun_get_cgroup_mode (err);
      if (UNLIKELY (cgroup_mode < 0))
        return cgroup_mode;

      if (cgroup_mode != CGROUP_MODE_UNIFIED)
        libcrun_warning ("cgroup v1 is deprecated and will be removed in a future release.  Use cgroup v2");
    }

  ret = setup_container_hooks_output (container, def, &container_args, &hooks_out_fd, &hooks_err_fd, err);
  if (UNLIKELY (ret < 0))
    return ret;

  container->context = context;

  if (! detach || context->notify_socket)
    {
      libcrun_debug ("Setting child subreaper");
      ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "prctl set child subreaper");
    }

  ret = setup_container_keyring (container, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = setup_terminal_socket_pair (container, context, &container_args, &socket_pair_0, &socket_pair_1, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  umask (0);

  ret = libcrun_set_mempolicy (def, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = setup_seccomp (container, seccomp_bpf_data, &seccomp_gen_ctx, &seccomp_fd, err);
  if (UNLIKELY (ret < 0))
    return ret;
  container_args.seccomp_fd = seccomp_fd;

  if (seccomp_fd >= 0)
    {
      ret = get_seccomp_receiver_fd (container, &container_args.seccomp_receiver_fd, &own_seccomp_receiver_fd,
                                     &seccomp_notify_plugins, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = setup_console_socket (context, def, &container_args, &console_socket_fd, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = setup_cgroup_manager (context, container, &cg, &cgroup_dirfd, &cgroup_dirfd_s, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_configure_handler (container_args.context->handler_manager,
                                   container_args.context,
                                   container,
                                   &(container_args.custom_handler),
                                   err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container_args.custom_handler && container_args.custom_handler->vtable->modify_oci_configuration)
    {
      libcrun_debug ("Using custom handler to modify OCI configuration");
      ret = container_args.custom_handler->vtable->modify_oci_configuration (container_args.custom_handler->cookie,
                                                                             container_args.context,
                                                                             container->container_def,
                                                                             err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  pid = libcrun_run_linux_container (container, container_init, &container_args, &sync_socket, &cgroup_dirfd_s, err);
  if (UNLIKELY (pid < 0))
    return pid;

  cg.pid = pid;
  cg.joined = cgroup_dirfd_s.joined;
  libcrun_debug ("Running container on PID: `%d`", pid);

  if (context->fifo_exec_wait_fd < 0 && context->notify_socket)
    {
      libcrun_debug ("Using notify socket: `%s`", context->notify_socket);
      /* Do not open the notify socket here on "create".  "start" will take care of it.  */
      ret = get_notify_fd (context, container, &notify_socket, err);
      if (UNLIKELY (ret < 0))
        goto fail;
    }

  if (container_args.terminal_socketpair[1] >= 0)
    close_and_reset (&socket_pair_1);

  ret = libcrun_cgroup_enter (&cg, &cgroup_status, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = libcrun_apply_intelrdt (context->id, container, pid, LIBCRUN_INTELRDT_CREATE_UPDATE_MOVE, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = libcrun_move_network_devices (container, pid, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  /* sync send own pid.  */
  ret = TEMP_FAILURE_RETRY (write (sync_socket, &pid, sizeof (pid)));
  if (UNLIKELY (ret != sizeof (pid)))
    {
      if (ret >= 0)
        errno = 0;
      crun_make_error (err, errno, "write to sync socket");
      goto fail;
    }

  /* sync 1.  */
  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  /* sync 2.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = libcrun_cgroup_enter_finalize (&cg, cgroup_status, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = set_scheduler (pid, def, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  /* The container is waiting that we write back.  In this phase we can launch the
     prestart hooks.  */
  if (def->hooks && def->hooks->prestart_len)
    {
      libcrun_debug ("Running `prestart` hooks");
      ret = do_hooks (def, pid, context->id, false, NULL, "created", "prestart", (hook **) def->hooks->prestart,
                      def->hooks->prestart_len, hooks_out_fd, hooks_err_fd, false, err);
      if (UNLIKELY (ret != 0))
        goto fail;
    }
  if (def->hooks && def->hooks->create_runtime_len)
    {
      libcrun_debug ("Running `create` hooks");
      ret = do_hooks (def, pid, context->id, false, NULL, "created", "createRuntime", (hook **) def->hooks->create_runtime,
                      def->hooks->create_runtime_len, hooks_out_fd, hooks_err_fd, false, err);
      if (UNLIKELY (ret != 0))
        goto fail;
    }

  ret = seccomp_generation (seccomp_fd, seccomp_bpf_data, &seccomp_gen_ctx, err);
  if (UNLIKELY (ret < 0))
    goto fail;
  close_and_reset (&seccomp_fd);

  /* sync 3.  */
  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = terminal_setup (def, context, socket_pair_0, &terminal_fd, &orig_terminal, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  close_and_reset (&socket_pair_0);

  /* sync 4.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = close_and_reset (&sync_socket);
  if (UNLIKELY (ret < 0))
    {
      crun_make_error (err, errno, "close sync_socket failed");
      goto fail;
    }

  libcrun_debug ("Writing container status");
  ret = write_container_status (container, context, pid, cgroup_status, err);
  if (UNLIKELY (ret < 0))
    goto fail;

  /* Run poststart hooks here only if the container is created using "run".  For create+start, the
     hooks will be executed as part of the start command.  */
  if (context->fifo_exec_wait_fd < 0 && def->hooks && def->hooks->poststart_len)
    {
      libcrun_debug ("Running `poststart` hooks");
      ret = do_hooks (def, pid, context->id, false, NULL, "running", "poststart", (hook **) def->hooks->poststart,
                      def->hooks->poststart_len, hooks_out_fd, hooks_err_fd, false, err);
      if (UNLIKELY (ret != 0))
        goto fail;
    }

  /* Let's receive the seccomp notify fd and handle it as part of wait_for_process().  */
  if (own_seccomp_receiver_fd >= 0)
    {
      libcrun_debug ("Receiving seccomp fd");
      seccomp_notify_fd = receive_fd_from_socket (own_seccomp_receiver_fd, err);
      if (UNLIKELY (seccomp_notify_fd < 0))
        goto fail;

      ret = close_and_reset (&own_seccomp_receiver_fd);
      if (UNLIKELY (ret < 0))
        {
          crun_make_error (err, errno, "close seccomp receiver fd failed");
          goto fail;
        }
    }

  {
    struct wait_for_process_args args = {
      .pid = pid,
      .context = context,
      .terminal_fd = terminal_fd,
      .notify_socket = notify_socket,
      .container_ready_fd = container_ready_fd,
      .seccomp_notify_fd = seccomp_notify_fd,
      .seccomp_notify_plugins = seccomp_notify_plugins,
    };
    ret = wait_for_process (&args, err);
  }
  if (! context->detach)
    {
      libcrun_error_t tmp_err = NULL;
      cleanup_watch (context, def, cgroup_status, 0, sync_socket, terminal_fd, &tmp_err);
      crun_error_release (&tmp_err);
    }

  return ret;

fail:
  ret = cleanup_watch (context, def, cgroup_status, pid, sync_socket, terminal_fd, err);
  if (cgroup_status)
    {
      libcrun_error_t tmp_err = NULL;
      libcrun_cgroup_destroy (cgroup_status, &tmp_err);
      crun_error_release (&tmp_err);
    }
  return ret;
}

static int
check_config_file (runtime_spec_schema_config_schema *def, libcrun_context_t *context, libcrun_error_t *err)
{
  if (UNLIKELY (def->linux == NULL))
    return crun_make_error (err, 0, "invalid config file, no `linux` block specified");

  if (context->handler == NULL)
    {
      if (UNLIKELY (def->root == NULL))
        return crun_make_error (err, 0, "invalid config file, no `root` block specified");
      if (UNLIKELY (def->mounts == NULL))
        return crun_make_error (err, 0, "invalid config file, no `mounts` block specified");
    }
  return 0;
}

static int
libcrun_copy_config_file (const char *id, const char *state_root, libcrun_container_t *container, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *dest_path = NULL;
  cleanup_free char *dir = NULL;
  cleanup_free char *buffer = NULL;
  size_t len;

  ret = libcrun_get_state_directory (&dir, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&dest_path, err, dir, "config.json", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->config_file == NULL && container->config_file_content == NULL)
    return crun_make_error (err, 0, "config file not specified");

  if (container->config_file == NULL)
    {
      libcrun_debug ("Writing config file to: `%s`", dest_path);
      ret = write_file (dest_path, container->config_file_content, strlen (container->config_file_content), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      libcrun_debug ("Reading config file: `%s`", container->config_file);
      ret = read_all_file (container->config_file, &buffer, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      libcrun_debug ("Writing config file to: `%s`", dest_path);
      ret = write_file (dest_path, buffer, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static void
force_delete_container_status (libcrun_context_t *context, runtime_spec_schema_config_schema *def)
{
  libcrun_error_t tmp_err = NULL;
  container_delete_internal (context, def, context->id, true, false, &tmp_err);
  crun_error_release (&tmp_err);
}

/* Serialize ERR to FD as an int errno followed by a NUL-terminated message.
   Used by forked children to report a failure to the parent process.  */
static void
write_error_to_pipe (int fd, libcrun_error_t *err)
{
  const char *msg = (*err)->msg;
  int errcode = crun_error_get_errno (err);

  TEMP_FAILURE_RETRY (write (fd, &errcode, sizeof (errcode)));
  TEMP_FAILURE_RETRY (write (fd, msg, strlen (msg) + 1));
}

int
libcrun_container_run (libcrun_context_t *context, libcrun_container_t *container, unsigned int options,
                       libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  int detach = context->detach;
  int container_ret_status[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  libcrun_error_t tmp_err = NULL;

  container->context = context;

  ret = validate_options (options, LIBCRUN_RUN_OPTIONS_PREFORK | LIBCRUN_RUN_OPTIONS_KEEP, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process && def->process->terminal && detach && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with --detach when a terminal is used");

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! detach && (options & LIBCRUN_RUN_OPTIONS_PREFORK) == 0)
    {
      ret = libcrun_copy_config_file (context->id, context->state_root, container, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcrun_container_run_internal (container, context, NULL, err);
      if (! (options & LIBCRUN_RUN_OPTIONS_KEEP))
        force_delete_container_status (context, def);
      return ret;
    }

  ret = pipe2 (container_ret_status, O_CLOEXEC);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ret_status[0];
  pipefd1 = container_ret_status[1];

  ret = fork ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fork");
  if (ret)
    {
      int status;
      close_and_reset (&pipefd1);

      waitpid_ignore_stopped (ret, NULL, 0);

      ret = TEMP_FAILURE_RETRY (read (pipefd0, &status, sizeof (status)));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "read from sync pipe");

      if (status < 0)
        {
          int errno_;
          char buf[512];
          ret = TEMP_FAILURE_RETRY (read (pipefd0, &errno_, sizeof (errno_)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read from sync pipe");

          ret = TEMP_FAILURE_RETRY (read (pipefd0, buf, sizeof (buf) - 1));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read from sync pipe");
          buf[ret] = '\0';

          return crun_make_error (err, errno_, "%s", buf);
        }

      return status;
    }

  close_and_reset (&pipefd0);

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");

  ret = libcrun_copy_config_file (context->id, context->state_root, container, &tmp_err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = libcrun_container_run_internal (container, context, NULL, &tmp_err);
  TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  if (UNLIKELY (ret < 0))
    goto fail;

  exit (EXIT_SUCCESS);
fail:

  if (! (options & LIBCRUN_RUN_OPTIONS_KEEP))
    force_delete_container_status (context, def);
  if (tmp_err)
    {
      write_error_to_pipe (pipefd1, &tmp_err);
      crun_error_release (&tmp_err);
    }

  exit (EXIT_FAILURE);
}

int
libcrun_container_create (libcrun_context_t *context, libcrun_container_t *container, unsigned int options,
                          libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  int container_ready_pipe[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int exec_fifo_fd = -1;
  context->detach = 1;

  libcrun_debug ("Creating container: `%s`", context->id);
  container->context = context;

  ret = validate_options (options, LIBCRUN_CREATE_OPTIONS_PREFORK, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process && def->process->terminal && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with create when a terminal is used");

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  exec_fifo_fd = libcrun_status_create_exec_fifo (context->state_root, context->id, err);
  if (UNLIKELY (exec_fifo_fd < 0))
    return exec_fifo_fd;

  context->fifo_exec_wait_fd = exec_fifo_fd;
  exec_fifo_fd = -1;

  if ((options & LIBCRUN_RUN_OPTIONS_PREFORK) == 0)
    {
      libcrun_debug ("Running with prefork enabled");
      ret = libcrun_copy_config_file (context->id, context->state_root, container, err);
      if (UNLIKELY (ret < 0))
        return ret;
      ret = libcrun_container_run_internal (container, context, NULL, err);
      if (UNLIKELY (ret < 0))
        force_delete_container_status (context, def);
      return ret;
    }

  ret = pipe2 (container_ready_pipe, O_CLOEXEC);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ready_pipe[0];
  pipefd1 = container_ready_pipe[1];

  ret = fork ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fork");
  if (ret)
    {
      int exit_code;
      close_and_reset (&pipefd1);

      waitpid_ignore_stopped (ret, NULL, 0);

      ret = TEMP_FAILURE_RETRY (read (pipefd0, &exit_code, sizeof (exit_code)));
      if (UNLIKELY (ret <= 0))
        return crun_make_error (err, ret < 0 ? errno : 0, "waiting for container to be ready");

      if (ret != sizeof (exit_code) || exit_code < 0)
        return crun_make_error (err, 0, "internal error: read invalid exit code");

      if (exit_code == 0)
        return 0;

      libcrun_debug ("Exit code is `%d`, deleting container", exit_code);
      libcrun_error_t tmp_err = NULL;
      libcrun_container_delete (context, def, context->id, true, &tmp_err);
      crun_error_release (&tmp_err);
      return crun_make_error (err, 0, "error creating container");
    }

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");

  ret = libcrun_copy_config_file (context->id, context->state_root, container, err);
  if (UNLIKELY (ret < 0))
    {
      int errcode = crun_error_get_errno (err);
      crun_error_release (err);
      libcrun_fail_with_error (errcode, "copy config file");
    }

  ret = libcrun_container_run_internal (container, context, &pipefd1, err);
  if (UNLIKELY (ret < 0))
    {
      force_delete_container_status (context, def);
      libcrun_error ((*err)->status, "%s", (*err)->msg);
      crun_error_release (err);
      crun_set_output_handler (log_write_to_stderr, NULL);
    }

  if (pipefd1 >= 0)
    TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  exit (ret ? EXIT_FAILURE : 0);
}

int
libcrun_container_start (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container = NULL;
  const char *state_root = context->state_root;
  runtime_spec_schema_config_schema *def;
  cleanup_container_status libcrun_container_status_t status = {};
  cleanup_close int fd = -1;
  int ret;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! ret)
    return crun_make_error (err, 0, "container `%s` is not running", id);

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (context->notify_socket)
    {
      ret = get_notify_fd (context, container, &fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_status_write_exec_fifo (context->state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  def = container->container_def;

  if (context->notify_socket)
    {
      if (fd >= 0)
        {
          fd_set read_set;

          while (1)
            {
              struct timeval timeout = {
                .tv_sec = 0,
                .tv_usec = 10000,
              };
              FD_ZERO (&read_set);
              FD_SET (fd, &read_set);

              ret = select (fd + 1, &read_set, NULL, NULL, &timeout);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "select failed");
              if (ret)
                {
                  ret = handle_notify_socket (fd, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (ret)
                    break;
                }
              else
                {
                  ret = libcrun_is_container_running (&status, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (! ret)
                    return 0;
                }
            }
        }
    }

  /* The container is considered running only after we got the notification from the
     notify_socket, if any.  */
  if (def->hooks && def->hooks->poststart_len)
    {
      cleanup_close int hooks_out_fd = -1;
      cleanup_close int hooks_err_fd = -1;

      ret = open_hooks_output (container, &hooks_out_fd, &hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_hooks (def, status.pid, context->id, false, status.bundle, "running", "poststart", (hook **) def->hooks->poststart,
                      def->hooks->poststart_len, hooks_out_fd, hooks_err_fd, false, err);
      if (UNLIKELY (ret != 0))
        {
          libcrun_error_t tmp_err = NULL;
          container_delete_internal (context, def, id, true, true, &tmp_err);
          crun_error_release (&tmp_err);
          return ret;
        }
    }

  return 0;
}

int
libcrun_get_container_state_string (const char *id, libcrun_container_status_t *status, const char *state_root,
                                    const char **container_status, int *running, libcrun_error_t *err)
{
  int ret, has_fifo = 0;
  bool paused = false;

  ret = libcrun_is_container_running (status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  *running = ret;

  if (*running)
    {
      ret = libcrun_status_has_read_exec_fifo (state_root, id, err);
      if (UNLIKELY (ret < 0))
        return ret;
      has_fifo = ret;
    }

  if (*running && ! has_fifo)
    {
      cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;

      cgroup_status = libcrun_cgroup_make_status (status);

      ret = libcrun_cgroup_is_container_paused (cgroup_status, &paused, err);
      if (UNLIKELY (ret < 0))
        {
          /*
            The cgroup might have been cleaned up by the time we try to read it, ignore both
            ENOENT and ENODEV:
            - ENOENT: if the open(CGROUP_PATH) fails because the cgroup was deleted.
            - ENODEV: if the cgroup is deleted between the open and reading the freeze status.
          */

          errno = crun_error_get_errno (err);
          if (errno == ENOENT || errno == ENODEV)
            {
              crun_error_release (err);
              *container_status = "stopped";
              return 0;
            }

          return ret;
        }
    }

  if (! *running)
    *container_status = "stopped";
  else if (has_fifo)
    *container_status = "created";
  else if (paused)
    *container_status = "paused";
  else
    *container_status = "running";

  return 0;
}

int
libcrun_container_state (libcrun_context_t *context, const char *id, FILE *out, libcrun_error_t *err)
{
  const char *const OCI_CONFIG_VERSION = "1.0.0";
  libcrun_container_status_t status = {};
  const char *state_root = context->state_root;
  const char *container_status = NULL;
  json_gen_ctx *gen = NULL;
  const char *buf;
  int ret = 0;
  int r = json_gen_status_ok;
  int running;
  size_t len;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_get_container_state_string (id, &status, state_root, &container_status, &running, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = 0;
  if (! json_gen_init (&gen, NULL))
    return crun_make_error (err, 0, "json_gen_init failed");

  json_gen_config (gen, json_gen_beautify, 1);

  GEN_OR_FAIL (json_gen_map_open (gen));
  GEN_KEY (gen, "ociVersion");
  GEN_STR (gen, OCI_CONFIG_VERSION);

  GEN_KEY (gen, "id");
  GEN_STR (gen, id);

  GEN_KEY (gen, "pid");
  GEN_OR_FAIL (map_int (gen, running ? status.pid : 0));

  GEN_KEY (gen, "status");
  GEN_STR (gen, container_status);

  GEN_KEY (gen, "bundle");
  GEN_STR (gen, status.bundle);

  GEN_KEY (gen, "rootfs");
  GEN_STR (gen, status.rootfs);

  GEN_KEY (gen, "created");
  GEN_STR (gen, status.created);

  if (status.scope)
    {
      GEN_KEY (gen, "systemd-scope");
      GEN_STR (gen, status.scope);
    }

  if (status.owner)
    {
      GEN_KEY (gen, "owner");
      GEN_STR (gen, status.owner);
    }

  {
    cleanup_container libcrun_container_t *container = NULL;

    ret = read_container_config_from_state (&container, state_root, id, err);
    if (UNLIKELY (ret < 0))
      goto exit;

    if (container->container_def->annotations && container->container_def->annotations->len)
      GEN_OR_FAIL (gen_annotations (gen, container->container_def->annotations));
  }

  GEN_OR_FAIL (json_gen_map_close (gen));

  GEN_OR_FAIL (json_gen_get_buf (gen, &buf, &len));

  fprintf (out, "%s\n", buf);

exit:
  if (gen)
    json_gen_free (gen);
  libcrun_free_container_status (&status);
  return ret;

gen_error:
  ret = json_gen_error_to_crun_error (r, err);
  goto exit;
}

int
libcrun_container_exec (libcrun_context_t *context, const char *id, runtime_spec_schema_config_schema_process *process,
                        libcrun_error_t *err)
{
  struct libcrun_container_exec_options_s opts;
  memset (&opts, 0, sizeof (opts));

  opts.struct_size = sizeof (opts);
  opts.process = process;

  return libcrun_container_exec_with_options (context, id, &opts, err);
}

int
libcrun_container_exec_process_file (libcrun_context_t *context, const char *id, const char *path, libcrun_error_t *err)
{
  struct libcrun_container_exec_options_s opts;
  memset (&opts, 0, sizeof (opts));

  opts.struct_size = sizeof (opts);
  opts.path = path;

  return libcrun_container_exec_with_options (context, id, &opts, err);
}

#define cleanup_process_schema __attribute__ ((cleanup (cleanup_process_schemap)))

static inline void
cleanup_process_schemap (runtime_spec_schema_config_schema_process **p)
{
  runtime_spec_schema_config_schema_process *process = *p;
  if (process)
    (void) free_runtime_spec_schema_config_schema_process (process);
}

/* Build the seccomp receiver payload (when needed), apply the seccomp profile and
   close the seccomp file descriptors.  Used from exec_process_entrypoint both before
   and after the capabilities are set, depending on process->no_new_privileges.  */
static int
apply_seccomp_for_exec (libcrun_container_t *container, pid_t own_pid, int seccomp_fd,
                        int seccomp_receiver_fd, char **seccomp_flags, size_t seccomp_flags_len,
                        libcrun_error_t *err)
{
  cleanup_free char *seccomp_fd_payload = NULL;
  size_t seccomp_fd_payload_len = 0;
  int ret;

  if (seccomp_receiver_fd >= 0)
    {
      ret = get_seccomp_receiver_fd_payload (container, "running", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_apply_seccomp (seccomp_fd, seccomp_receiver_fd, seccomp_fd_payload,
                               seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  close_and_reset (&seccomp_fd);
  close_and_reset (&seccomp_receiver_fd);
  return 0;
}

static int
exec_process_entrypoint (libcrun_context_t *context,
                         libcrun_container_t *container,
                         runtime_spec_schema_config_schema_process *process,
                         int *pipefd1,
                         int seccomp_fd,
                         int seccomp_receiver_fd,
                         struct custom_handler_instance_s *custom_handler,
                         bool merge_env,
                         libcrun_error_t *err)
{
  runtime_spec_schema_config_schema_process_capabilities *capabilities = NULL;
  cleanup_free char *exec_path = NULL;
  uid_t container_uid;
  gid_t container_gid;
  const char *cwd;
  bool chdir_done = false;
  size_t seccomp_flags_len = 0;
  char **seccomp_flags = NULL;
  pid_t own_pid = 0;
  size_t i;
  int ret;

  container_uid = process->user ? process->user->uid : 0;
  container_gid = process->user ? process->user->gid : 0;

  TEMP_FAILURE_RETRY (read (*pipefd1, &own_pid, sizeof (own_pid)));

  cwd = process->cwd ? process->cwd : "/";
  if (LIKELY (libcrun_safe_chdir (cwd, err) == 0))
    chdir_done = true;
  else
    crun_error_release (err);

  ret = unblock_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = clearenv ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "clearenv");

  if ((merge_env || ! process->env_len) && container->container_def->process && container->container_def->process->env_len)
    {
      char *e;

      for (i = 0; i < container->container_def->process->env_len; i++)
        {
          e = container->container_def->process->env[i];
          if (putenv (e) < 0)
            return crun_make_error (err, errno, "putenv `%s`", e);
        }
    }
  if (process->env_len)
    {
      for (i = 0; i < process->env_len; i++)
        if (putenv (process->env[i]) < 0)
          return crun_make_error (err, errno, "putenv `%s`", process->env[i]);
    }

  if (getenv ("HOME") == NULL)
    {
      ret = set_home_env (container_uid);
      if (UNLIKELY (ret < 0))
        {
          libcrun_warning ("cannot detect HOME environment variable, setting default");
          if (UNLIKELY (setenv ("HOME", "/", 1) < 0))
            return crun_make_error (err, errno, "setenv HOME");
        }
    }

  ret = libcrun_set_selinux_label (container, process, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_apparmor_profile (container, process, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->container_def->linux && container->container_def->linux->seccomp)
    {
      seccomp_flags = container->container_def->linux->seccomp->flags;
      seccomp_flags_len = container->container_def->linux->seccomp->flags_len;
    }

  ret = find_executable (&exec_path, process->args[0], process->cwd, err);
  if (UNLIKELY (ret < 0))
    {
      if (crun_error_get_errno (err) == ENOENT)
        return ret;

      /* If it fails for any other reason, ignore the failure.  We'll try again the lookup
         once the process switched to the use that runs in the container.  This might be necessary
         when opening a file that is on a network file system like NFS, where CAP_DAC_OVERRIDE
         is not honored.  */
      crun_error_release (err);
    }

  if (container->container_def->linux && container->container_def->linux->personality)
    {
      ret = libcrun_set_personality (container->container_def->linux->personality, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = mark_or_close_fds_ge_than (container, context->preserve_fds + 3, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! process->no_new_privileges)
    {
      ret = apply_seccomp_for_exec (container, own_pid, seccomp_fd, seccomp_receiver_fd,
                                    seccomp_flags, seccomp_flags_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_container_setgroups (container, process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = maybe_chown_std_streams (container_uid, container_gid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (process->capabilities)
    capabilities = process->capabilities;
  else if (container->container_def->process)
    capabilities = container->container_def->process->capabilities;

  ret = libcrun_set_caps (capabilities, container_uid, container_gid, process->no_new_privileges, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (exec_path == NULL))
    {
      ret = find_executable (&exec_path, process->args[0], process->cwd, err);
      if (UNLIKELY (ret < 0))
        {
          if (custom_handler == NULL || is_empty_string (process->args[0]))
            return ret;

          /* If a custom handler is used, pass argv0 as specified.  e.g. with wasm the file could miss the +x bit.  */
          crun_error_release (err);
          exec_path = xstrdup (process->args[0]);
        }
    }

  if (! chdir_done)
    {
      ret = libcrun_safe_chdir (cwd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (process->no_new_privileges)
    {
      ret = apply_seccomp_for_exec (container, own_pid, seccomp_fd, seccomp_receiver_fd,
                                    seccomp_flags, seccomp_flags_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (process->user)
    umask (process->user->umask_present ? process->user->umask : 0022);

  ret = 0;
  TEMP_FAILURE_RETRY (write (*pipefd1, &ret, sizeof (ret)));
  TEMP_FAILURE_RETRY (close (*pipefd1));
  *pipefd1 = -1;

  if (custom_handler)
    {
      if (custom_handler->vtable->exec_func == NULL)
        return crun_make_error (err, 0, "the handler does not support exec");

      ret = custom_handler->vtable->exec_func (custom_handler->cookie,
                                               container,
                                               exec_path,
                                               process->args);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "exec container process failed with handler as `%s`", custom_handler->vtable->name);

      _safe_exit (EXIT_FAILURE);
    }

  /* Attempt to close all the files that are not needed to prevent execv to have access to them.
     This is a best effort operation, because the seccomp filter is already in place and it could
     stop some syscalls used by mark_or_close_fds_ge_than.
  */
  ret = mark_or_close_fds_ge_than (container, context->preserve_fds + 3, true, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  TEMP_FAILURE_RETRY (execv (exec_path, process->args));
  libcrun_fail_with_error (errno, "exec `%s`", exec_path);
}

int
libcrun_container_exec_with_options (libcrun_context_t *context, const char *id,
                                     struct libcrun_container_exec_options_s *opts,
                                     libcrun_error_t *err)
{
  cleanup_custom_handler_instance struct custom_handler_instance_s *custom_handler = NULL;
  int container_status, ret;
  bool container_paused = false;
  pid_t pid;
  libcrun_container_status_t status = {};
  const char *state_root = context->state_root;
  cleanup_close int terminal_fd = -1;
  cleanup_close int seccomp_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  int container_ret_status[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int seccomp_receiver_fd = -1;
  cleanup_close int own_seccomp_receiver_fd = -1;
  cleanup_close int seccomp_notify_fd = -1;
  const char *seccomp_notify_plugins = NULL;
  __attribute__ ((unused)) cleanup_process_schema runtime_spec_schema_config_schema_process *process_cleanup = NULL;
  runtime_spec_schema_config_schema_process *process = opts->process;
  struct libcrun_seccomp_gen_ctx_s seccomp_gen_ctx;
  int ret_from_child = 0;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  container_status = ret;

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  container->context = context;

  if (container_status == 0)
    return crun_make_error (err, 0, "the container `%s` is not running", id);

  {
    cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;

    cgroup_status = libcrun_cgroup_make_status (&status);

    ret = libcrun_cgroup_is_container_paused (cgroup_status, &container_paused, err);
    if (UNLIKELY (ret < 0))
      return ret;
  }

  if (UNLIKELY (container_paused))
    return crun_make_error (err, 0, "cannot exec in a paused container `%s`", id);

  ret = libcrun_configure_handler (context->handler_manager,
                                   context,
                                   container,
                                   &custom_handler,
                                   err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  libcrun_seccomp_gen_ctx_init (&seccomp_gen_ctx, container, false, 0);

  ret = libcrun_open_seccomp_bpf (&seccomp_gen_ctx, &seccomp_fd, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (seccomp_fd >= 0)
    {
      ret = get_seccomp_receiver_fd (container, &seccomp_receiver_fd,
                                     &own_seccomp_receiver_fd,
                                     &seccomp_notify_plugins, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (sizeof (*opts) != opts->struct_size)
    return crun_make_error (err, EINVAL, "invalid libcrun_container_exec_options_s struct");

  if (opts->path)
    {
      struct parser_context ctx = { 0, stderr };
      cleanup_free char *content = NULL;
      parser_error parser_err = NULL;
      json_object *doc = NULL;
      size_t len;

      if (process)
        return crun_make_error (err, EINVAL, "cannot specify both exec file and options");

      ret = read_all_file (opts->path, &content, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = parse_json_file (&doc, content, &ctx, err);
      if (UNLIKELY (ret < 0))
        return ret;

      process = make_runtime_spec_schema_config_schema_process (doc, &ctx, &parser_err);
      if (UNLIKELY (process == NULL))
        {
          ret = crun_make_error (err, 0, "cannot parse process file: `%s`", parser_err);
          free (parser_err);
          if (doc)
            json_object_put (doc);
          return ret;
        }

      free (parser_err);
      if (doc)
        json_object_put (doc);

      process_cleanup = process;
    }

  /* This must be done before we enter a user namespace.  */
  ret = libcrun_set_rlimits (process->rlimits, process->rlimits_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = pipe2 (container_ret_status, O_CLOEXEC);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ret_status[0];
  pipefd1 = container_ret_status[1];

  /* If the new process block doesn't specify a SELinux label, AppArmor profile or user, then
     use the configuration from the original config file.  */
  if (container->container_def->process)
    {
      if (process->selinux_label == NULL && container->container_def->process->selinux_label)
        process->selinux_label = xstrdup (container->container_def->process->selinux_label);

      if (process->apparmor_profile == NULL && container->container_def->process->apparmor_profile)
        process->apparmor_profile = xstrdup (container->container_def->process->apparmor_profile);

      if (process->user == NULL && container->container_def->process->user)
        {
          process->user = clone_runtime_spec_schema_config_schema_process_user (container->container_def->process->user);
          if (process->user == NULL)
            OOM ();
        }
    }

  ret = initialize_security (container, process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = prctl (PR_SET_DUMPABLE, 0, 0, 0, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "prctl unset dumpable");

  pid = libcrun_join_process (context, container, status.pid, &status, opts->cgroup, context->detach,
                              process, process->terminal ? &terminal_fd : NULL, err);
  if (UNLIKELY (pid < 0))
    return pid;

  /* Process to exec.  */
  if (pid == 0)
    {
      TEMP_FAILURE_RETRY (close (pipefd0));
      pipefd0 = -1;

      exec_process_entrypoint (context, container, process, &pipefd1, seccomp_fd, seccomp_receiver_fd, custom_handler, opts->merge_env, err);
      /* It gets here only on errors.  */
      if (*err)
        {
          if (pipefd1 < 0)
            libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
          else
            {
              write_error_to_pipe (pipefd1, err);
              TEMP_FAILURE_RETRY (close (pipefd1));
              pipefd1 = -1;
            }
        }
      _safe_exit (EXIT_FAILURE);
    }

  TEMP_FAILURE_RETRY (close (pipefd1));
  pipefd1 = -1;

  TEMP_FAILURE_RETRY (write (pipefd0, &pid, sizeof (pid)));

  if (seccomp_fd >= 0)
    close_and_reset (&seccomp_fd);

  if (terminal_fd >= 0)
    {
      unsigned short rows = 0, cols = 0;

      if (process->console_size)
        {
          cols = process->console_size->width;
          rows = process->console_size->height;
        }

      ret = libcrun_terminal_setup_size (terminal_fd, rows, cols, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (context->console_socket)
        {
          int ret;
          cleanup_close int console_socket_fd = open_unix_domain_client_socket (context->console_socket, 0, err);
          if (UNLIKELY (console_socket_fd < 0))
            return console_socket_fd;
          ret = send_fd_to_socket (console_socket_fd, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close_and_reset (&terminal_fd);
        }
      else
        {
          ret = libcrun_set_raw (0, &orig_terminal, err);
          if (UNLIKELY (ret < 0))
            {
              flush_fd_to_err (context, terminal_fd);
              return ret;
            }
        }
    }

  ret = TEMP_FAILURE_RETRY (read (pipefd0, &ret_from_child, sizeof (ret_from_child)));
  if (ret != sizeof (ret_from_child))
    ret = crun_make_error (err, 0, "read pipe failed");
  else if (ret_from_child != 0)
    {
      cleanup_free char *msg = NULL;
      size_t len = 0;

      ret = read_all_fd (pipefd0, "error stream", &msg, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      /* the string from read_all_fd is always NUL terminated.  */
      ret = crun_make_error (err, ret_from_child, "%s", msg);
    }
  else
    {
      /* Let's receive the seccomp notify fd and handle it as part of wait_for_process().  */
      if (own_seccomp_receiver_fd >= 0)
        {
          seccomp_notify_fd = receive_fd_from_socket (own_seccomp_receiver_fd, err);
          if (UNLIKELY (seccomp_notify_fd < 0))
            return seccomp_notify_fd;

          ret = close_and_reset (&own_seccomp_receiver_fd);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "close seccomp receiver fd failed");
        }

      {
        struct wait_for_process_args args = {
          .pid = pid,
          .context = context,
          .terminal_fd = terminal_fd,
          .notify_socket = -1,
          .container_ready_fd = NULL,
          .seccomp_notify_fd = seccomp_notify_fd,
          .seccomp_notify_plugins = seccomp_notify_plugins,
        };

        ret = wait_for_process (&args, err);
      }
    }

  flush_fd_to_err (context, terminal_fd);
  return ret;
}

int
libcrun_container_update (libcrun_context_t *context, const char *id, const char *content, size_t len arg_unused,
                          libcrun_error_t *err)
{
  cleanup_custom_handler_instance struct custom_handler_instance_s *custom_handler = NULL;
  runtime_spec_schema_config_linux_resources *resources = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  const char *state_root = context->state_root;
  struct parser_context ctx = { 0, stderr };
  libcrun_container_status_t status = {};
  parser_error parser_err = NULL;
  json_object *doc = NULL;
  int ret;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_configure_handler (context->handler_manager,
                                   context,
                                   container,
                                   &custom_handler,
                                   err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = parse_json_file (&doc, content, &ctx, err);
  if (UNLIKELY (ret < 0))
    return ret;

  resources = make_runtime_spec_schema_config_linux_resources (doc, &ctx, &parser_err);
  if (UNLIKELY (resources == NULL))
    {
      ret = crun_make_error (err, 0, "cannot parse resources: %s", parser_err);
      goto cleanup;
    }

  if (custom_handler && custom_handler->vtable->modify_oci_configuration)
    {
      /* Adapt RESOURCES to be used from the modify_oci_configuration hook.  */
      cleanup_free runtime_spec_schema_config_linux *linux = xmalloc0 (sizeof (*linux));
      cleanup_free runtime_spec_schema_config_schema *def = xmalloc0 (sizeof (*def));

      def->linux = linux;
      linux->resources = resources;

      ret = custom_handler->vtable->modify_oci_configuration (custom_handler->cookie,
                                                              context,
                                                              def,
                                                              err);
      if (UNLIKELY (ret < 0))
        goto cleanup;
    }

  ret = libcrun_linux_container_update (&status, state_root, resources, err);

cleanup:
  if (doc)
    json_object_put (doc);
  free (parser_err);
  if (resources)
    free_runtime_spec_schema_config_linux_resources (resources);

  return ret;
}

int
libcrun_container_update_from_file (libcrun_context_t *context, const char *id, const char *file, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  size_t len;
  int ret;

  ret = read_all_file (file, &content, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_container_update (context, id, content, len, err);
}

static int
compare_update_values (const void *a, const void *b)
{
  const struct libcrun_update_value_s *aa = a;
  const struct libcrun_update_value_s *bb = b;
  int ret;

  ret = strcmp (aa->section, bb->section);
  if (ret)
    return ret;
  return strcmp (aa->name, bb->name);
}

int
libcrun_container_update_from_values (libcrun_context_t *context, const char *id,
                                      struct libcrun_update_value_s *values, size_t len,
                                      libcrun_error_t *err)
{
  const char *current_section = NULL;
  const char *buf;
  json_gen_ctx *gen = NULL;
  size_t i, buf_len;
  int ret;

  if (! json_gen_init (&gen, NULL))
    return crun_make_error (err, 0, "json_gen_init failed");
  json_gen_map_open (gen);

  qsort (values, len, sizeof (struct libcrun_update_value_s), compare_update_values);

  for (i = 0; i < len; i++)
    {
      if (current_section == NULL || strcmp (values[i].section, current_section))
        {
          if (i > 0)
            json_gen_map_close (gen);

          current_section = values[i].section;
          json_gen_string (gen, current_section, strlen (current_section));
          json_gen_map_open (gen);
        }

      json_gen_string (gen, values[i].name, strlen (values[i].name));

      if (values[i].numeric)
        json_gen_number (gen, values[i].value, strlen (values[i].value));
      else
        json_gen_string (gen, values[i].value, strlen (values[i].value));
    }
  if (len)
    json_gen_map_close (gen);

  json_gen_map_close (gen);

  json_gen_get_buf (gen, &buf, &buf_len);

  ret = libcrun_container_update (context, id, buf, buf_len, err);

  json_gen_free (gen);

  return ret;
}

static void
populate_array_field (char ***field, char *array[], size_t num_elements)
{
  size_t i;

  *field = xmalloc0 ((num_elements + 1) * sizeof (char *));
  for (i = 0; i < num_elements; i++)
    (*field)[i] = xstrdup (array[i]);

  (*field)[i] = NULL;
}

#ifdef HAVE_CAP
static void
populate_capabilities (struct features_info_s *info, char ***capabilities, size_t *num_capabilities)
{
  size_t index = 0;
  cap_value_t i;
  char *endptr;
  int j;

  *num_capabilities = 0;
  for (i = 0;; i++)
    {
      char *v = cap_to_name (i);
      if (v == NULL)
        break;
      strtol (v, &endptr, 10);
      if (endptr != v)
        {
          // Non-numeric or non-zero value encountered, break the loop
          break;
        }
      (*num_capabilities)++;
    }

  *capabilities = xmalloc0 ((*num_capabilities + 1) * sizeof (const char *));
  for (i = 0; i < (cap_value_t) *num_capabilities; i++)
    {
      char *v = cap_to_name (i);
      if (v == NULL)
        break;
      strtol (v, &endptr, 10);
      if (endptr != v)
        {
          // Non-numeric or non-zero value encountered, break the loop
          break;
        }

      // Convert capability name to uppercase
      for (j = 0; v[j] != '\0'; j++)
        v[j] = toupper (v[j]);

      (*capabilities)[index] = v;
      index++;
    }

  (*capabilities)[index] = NULL; // Terminate the array with NULL
  populate_array_field (&(info->linux.capabilities), *capabilities, *num_capabilities);
}
#endif

static void
retrieve_mount_options (struct features_info_s **info)
{
  cleanup_free const struct propagation_flags_s *mount_options_list = NULL;
  size_t num_mount_options = 0;

  // Retrieve mount options from wordlist
  mount_options_list = get_mount_flags_from_wordlist ();

  // Calculate the number of mount options
  while (mount_options_list[num_mount_options].name != NULL)
    num_mount_options++;

  // Allocate memory for mount options in info struct
  (*info)->mount_options = xmalloc0 ((num_mount_options + 1) * sizeof (char *));

  // Copy mount options to info struct
  for (size_t i = 0; i < num_mount_options; i++)
    (*info)->mount_options[i] = xstrdup (mount_options_list[i].name);
}

int
libcrun_container_get_features (libcrun_context_t *context, struct features_info_s **info, libcrun_error_t *err arg_unused)
{
  // Allocate memory for the features_info_s structure
  size_t num_namspaces = sizeof (namespaces) / sizeof (namespaces[0]);
  size_t num_operators = sizeof (operators) / sizeof (operators[0]);
  size_t num_actions = sizeof (actions) / sizeof (actions[0]);
  size_t num_hooks = sizeof (hooks) / sizeof (hooks[0]);
  size_t num_archs = sizeof (archs) / sizeof (archs[0]);
  size_t num_unsafe_annotations = sizeof (potentially_unsafe_annotations) / sizeof (potentially_unsafe_annotations[0]);
  cleanup_free char **capabilities = NULL;
  size_t num_capabilities = 0;
  size_t num_mempolicy_modes = sizeof (mempolicy_modes) / sizeof (mempolicy_modes[0]);
  size_t num_mempolicy_flags = sizeof (mempolicy_flags) / sizeof (mempolicy_flags[0]);

  *info = xmalloc0 (sizeof (struct features_info_s));

  // Hardcoded feature information
  (*info)->oci_version_min = xstrdup ("1.0.0");
  (*info)->oci_version_max = xstrdup ("1.1.0+dev");

  // Populate hooks
  populate_array_field (&((*info)->hooks), hooks, num_hooks);

  // Populate mount_options
  retrieve_mount_options (info);

  // Populate namespaces
  populate_array_field (&((*info)->linux.namespaces), namespaces, num_namspaces);

#ifdef HAVE_CAP
  // Populate capabilities
  populate_capabilities (*info, &capabilities, &num_capabilities);
#endif

  // Hardcode the values for cgroup
  (*info)->linux.cgroup.v1 = true;
  (*info)->linux.cgroup.v2 = true;
#ifdef HAVE_SYSTEMD
  (*info)->linux.cgroup.systemd = true;
  (*info)->linux.cgroup.systemd_user = true;
#endif

  // Put seccomp values
#ifdef HAVE_SECCOMP
  (*info)->linux.seccomp.enabled = true;
  // Populate actions
  populate_array_field (&((*info)->linux.seccomp.actions), actions, num_actions);
  // Populate operators
  populate_array_field (&((*info)->linux.seccomp.operators), operators, num_operators);
  // Populate archs
  populate_array_field (&((*info)->linux.seccomp.archs), archs, num_archs);
#else
  (*info)->linux.seccomp.enabled = false;
#endif

  // Put values for apparmor and selinux
  (*info)->linux.apparmor.enabled = true;
  (*info)->linux.selinux.enabled = true;

  (*info)->linux.intel_rdt.enabled = true;

  (*info)->linux.net_devices.enabled = true;

  populate_array_field (&((*info)->linux.memory_policy.mode), mempolicy_modes, num_mempolicy_modes);
  populate_array_field (&((*info)->linux.memory_policy.flags), mempolicy_flags, num_mempolicy_flags);

  // Put the values for mount extensions
  (*info)->linux.mount_ext.idmap.enabled = true;

  // Populate the values for annotations
#ifdef HAVE_SECCOMP
  {
    const struct scmp_version *version = seccomp_version ();
    char *version_string = NULL;

    xasprintf (&version_string, "%u.%u.%u", version->major, version->minor, version->micro);
    (*info)->annotations.io_github_seccomp_libseccomp_version = version_string;
  }
#endif

  if (context->handler_manager && handler_by_name (context->handler_manager, "wasm"))
    (*info)->annotations.run_oci_crun_wasm = true;

#if HAVE_CRIU
  (*info)->annotations.run_oci_crun_checkpoint_enabled = true;
#endif
  (*info)->annotations.run_oci_crun_commit = GIT_VERSION;
  (*info)->annotations.run_oci_crun_version = PACKAGE_VERSION;

  populate_array_field (&((*info)->potentially_unsafe_annotations), potentially_unsafe_annotations, num_unsafe_annotations);

  return 0;
}

/* Read the container status and fail if the container is not running.  */
static int
read_status_require_running (libcrun_context_t *context, const char *id,
                             libcrun_container_status_t *status, libcrun_error_t *err)
{
  int ret;

  ret = libcrun_read_container_status (status, context->state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret == 0)
    return crun_make_error (err, 0, "the container `%s` is not running", id);

  return 0;
}

int
libcrun_container_pause (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status = {};

  ret = read_status_require_running (context, id, &status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_container_pause_linux (&status, err);
}

int
libcrun_container_unpause (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status = {};

  ret = read_status_require_running (context, id, &status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_container_unpause_linux (&status, err);
}

int
libcrun_container_checkpoint (libcrun_context_t *context, const char *id, libcrun_checkpoint_restore_t *cr_options,
                              libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  libcrun_container_status_t status = {};
  cleanup_container libcrun_container_t *container = NULL;

  ret = read_status_require_running (context, id, &status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Needed to use the same paths (e.g. the shared empty directory used for
     masked paths) as the container runtime and restore do.  */
  container->context = context;

  ret = libcrun_container_checkpoint_linux (&status, container, cr_options, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! (cr_options->leave_running || cr_options->pre_dump))
    return container_delete_internal (context, NULL, id, true, true, err);

  return 0;
}

static int
restore_proxy_process (int *proxy_pid_pipe, int cgroup_manager, libcrun_error_t *err)
{
  cleanup_free char *own_cgroup_copy = NULL;
  cleanup_free char *own_cgroup = NULL;
  const char *parent_cgroup;
  pid_t new_pid;
  int mode;
  int ret;

  ret = TEMP_FAILURE_RETRY (read (*proxy_pid_pipe, &new_pid, sizeof (new_pid)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read failed");

  close_and_reset (proxy_pid_pipe);

  if (cgroup_manager == CGROUP_MANAGER_SYSTEMD)
    {
      char ready_str[64];

      ret = snprintf (ready_str, sizeof (ready_str), "MAINPID=%d", new_pid);
      if (UNLIKELY (ret >= (int) sizeof (ready_str)))
        return crun_make_error (err, 0, "internal error: static buffer too small");

      ret = send_sd_notify (ready_str, err);
      /* Do not fail on errors.  */
      if (UNLIKELY (ret < 0))
        crun_error_release (err);
    }

  ret = libcrun_get_cgroup_process (0, &own_cgroup, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  own_cgroup_copy = xstrdup (own_cgroup);
  parent_cgroup = dirname (own_cgroup_copy);

  ret = libcrun_move_process_to_cgroup (0, 0, parent_cgroup, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (mode < 0))
    return mode;

  ret = destroy_cgroup_path (own_cgroup, mode, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

int
libcrun_container_restore (libcrun_context_t *context, const char *id, libcrun_checkpoint_restore_t *cr_options,
                           unsigned int options, libcrun_error_t *err)
{
  cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  cleanup_close int proxy_pid_pipe0 = -1;
  cleanup_close int proxy_pid_pipe1 = -1;
  runtime_spec_schema_config_schema *def;
  libcrun_container_status_t status = {};
  cleanup_pid pid_t proxy_pid = -1;
  int proxy_pid_pipe[2];
  int cgroup_manager;
  uid_t root_uid = -1;
  gid_t root_gid = -1;
  int ret;

  ret = validate_options (options, LIBCRUN_RESTORE_OPTIONS_PREFORK, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* CRIU restores the container as a child of the process driving it, which
     must also join the container cgroup for the time of the restore.  Without
     LIBCRUN_RESTORE_OPTIONS_PREFORK the calling process can be taken over and
     do that itself, the way `crun restore` does; with it, a throw-away process
     is used instead, and as that process cannot stay around to wait for the
     container, `detach` is required.  */
  if ((options & LIBCRUN_RESTORE_OPTIONS_PREFORK) && ! cr_options->detach)
    return crun_make_error (err, EINVAL, "`detach` is required with `LIBCRUN_RESTORE_OPTIONS_PREFORK`");

  container = libcrun_container_load_from_file ("config.json", err);
  if (container == NULL)
    return -1;

  container->context = context;
  def = container->container_def;

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_copy_config_file (context->id, context->state_root, container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  cgroup_manager = CGROUP_MANAGER_CGROUPFS;
  if (context->systemd_cgroup)
    cgroup_manager = CGROUP_MANAGER_SYSTEMD;
  else if (context->force_no_cgroup)
    cgroup_manager = CGROUP_MANAGER_DISABLED;

  def = container->container_def;

  /* If we are root (either on the host or in a namespace),
   * then chown the cgroup to root in the container user namespace. */
  get_root_in_the_userns (def, container->host_uid, container->host_gid, &root_uid, &root_gid);

  /* If the root in the container is different than the current root user, attempt to chown
     the std streams before entering the user namespace.  Otherwise we might lose access
     to the user (as it is not mapped in the user namespace) and cannot chown them.  */
  if (root_uid > 0 || root_gid > 0)
    {
      ret = maybe_chown_std_streams (root_uid, root_gid, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  {
    cleanup_close int cgroup_dirfd = -1;
    bool needs_proxy_process;
    struct libcrun_cgroup_args cg = {
      .resources = def->linux ? def->linux->resources : NULL,
      .annotations = container->annotations,
      .cgroup_path = def->linux ? def->linux->cgroups_path : "",
      .manager = cgroup_manager,
      .root_uid = root_uid,
      .root_gid = root_gid,
      .id = context->id,
      .state_root = context->state_root,
      .container = container,
    };

    /* The CRIU restore code uses bundle, rootfs and cgroup_path of status.   The cgroup_path is set later.  */
    status.bundle = (char *) context->bundle;
    status.rootfs = def->root->path;

    ret = libcrun_cgroup_preenter (&cg, &cgroup_dirfd, err);
    if (UNLIKELY (ret < 0))
      return ret;

    needs_proxy_process = cgroup_dirfd < 0;

    /* If the target cgroup was already created (with cgroupfs), we can restore the container directly there.  */
    if (! needs_proxy_process)
      {
        cleanup_free char *cgroup_path = NULL;

        ret = get_cgroup_dirfd_path (cgroup_dirfd, &cgroup_path, err);
        if (UNLIKELY (ret < 0))
          return ret;

        /* Restore the container directly in the desired cgroup.  */
        status.cgroup_path = cgroup_path;

        ret = libcrun_container_restore_linux (&status, container, cr_options, options, err);
        if (UNLIKELY (ret < 0))
          return ret;

        /* Use the container first process PID to setup the cgroup.  The
           restored processes are already in the cgroup, as CRIU was run
           there, and the controllers were enabled by precreate_cgroup.  */
        cg.pid = status.pid;
        cg.joined = true;
      }
    else
      {
        /* When using systemd, we need a process first that must exist before a cgroup is created.
           Create a dummy process that sits and waits to receive the pid of the restored container.
           Once the dummy process receives the pid, the dummy process will notify the new pid to systemd.  */
        ret = pipe2 (proxy_pid_pipe, O_CLOEXEC);
        if (UNLIKELY (ret < 0))
          return crun_make_error (err, errno, "pipe");

        /* Only used for auto cleanup.  */
        proxy_pid_pipe0 = proxy_pid_pipe[0];
        proxy_pid_pipe1 = proxy_pid_pipe[1];

        proxy_pid = fork ();
        if (UNLIKELY (proxy_pid < 0))
          return crun_make_error (err, errno, "fork");

        if (proxy_pid == 0)
          {
            close_and_reset (&proxy_pid_pipe1);

            ret = restore_proxy_process (&proxy_pid_pipe0, cgroup_manager, err);
            if (UNLIKELY (ret < 0))
              {
                crun_error_release (err);
                _safe_exit (EXIT_FAILURE);
              }
            _safe_exit (EXIT_SUCCESS);
          }

        close_and_reset (&proxy_pid_pipe0);

        /* Use the dummy process PID as the PID to setup the cgroup.  */
        cg.pid = proxy_pid;
      }

    /* Complete the configuration for the cgroup.  It either contains the fully restored container with cgroupfs,
       or the dummy process with systemd.  */

    ret = libcrun_cgroup_enter (&cg, &cgroup_status, err);
    if (UNLIKELY (ret < 0))
      return ret;

    ret = libcrun_cgroup_enter_finalize (&cg, cgroup_status, err);
    if (UNLIKELY (ret < 0))
      return ret;

    /* When using a dummy process, the container is restored here once the cgroup is configured.  */
    if (needs_proxy_process)
      {
        cleanup_free char *target_cgroup = NULL;
        cleanup_free char *proxy_cgroup = NULL;

        ret = libcrun_get_cgroup_process (proxy_pid, &target_cgroup, false, err);
        if (UNLIKELY (ret < 0))
          return ret;

        /* Move the dummy process to a sub-cgroup.  */
        ret = append_paths (&proxy_cgroup, err, target_cgroup, ".proxy-crun", NULL);
        if (UNLIKELY (ret < 0))
          return ret;

        ret = libcrun_move_process_to_cgroup (proxy_pid, 0, proxy_cgroup, true, err);
        if (UNLIKELY (ret < 0))
          return ret;

        /* Restore the container in the same cgroup where the dummy process was.  */
        status.cgroup_path = target_cgroup;

        ret = libcrun_container_restore_linux (&status, container, cr_options, options, err);
        if (UNLIKELY (ret < 0))
          return ret;

        /* Notify the dummy process of the container PID.  It will move itself to its parent cgroup and
           destroy the cgroup.  */
        ret = TEMP_FAILURE_RETRY (write (proxy_pid_pipe1, &status.pid, sizeof (status.pid)));
        if (UNLIKELY (ret < 0))
          return crun_make_error (err, errno, "write pid to proxy process");
        close_and_reset (&proxy_pid_pipe1);

        ret = TEMP_FAILURE_RETRY (waitpid (proxy_pid, NULL, 0));
        if (ret < 0)
          return crun_make_error (err, errno, "waitpid");

        /* Do not kill the proxy process prematurely.  */
        proxy_pid = -1;
      }
  }

  context->detach = cr_options->detach;
  ret = write_container_status (container, context, status.pid, cgroup_status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (context->pid_file)
    {
      ret = write_pid_file (context->pid_file, status.pid, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (! cr_options->detach)
    {
      int wait_status;
      ret = waitpid_ignore_stopped (status.pid, &wait_status, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "waitpid failed for container `%s` with %d", id, ret);

      return get_process_exit_status (wait_status);
    }

  return 0;
}

int
libcrun_container_read_pids (libcrun_context_t *context, const char *id, bool recurse, pid_t **pids, libcrun_error_t *err)
{
  cleanup_cgroup_status struct libcrun_cgroup_status *cgroup_status = NULL;
  cleanup_container_status libcrun_container_status_t status = {};
  int ret;

  ret = libcrun_read_container_status (&status, context->state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (status.cgroup_path == NULL || status.cgroup_path[0] == '\0')
    return crun_make_error (err, 0, "the container is not using cgroups");

  cgroup_status = libcrun_cgroup_make_status (&status);

  return libcrun_cgroup_read_pids (cgroup_status, recurse, pids, err);
}

int
libcrun_write_json_containers_list (libcrun_context_t *context, FILE *out, libcrun_error_t *err)
{
  libcrun_container_list_t *list = NULL, *it;
  const char *content = NULL;
  json_gen_ctx *gen = NULL;
  size_t len;
  int ret;

  ret = libcrun_get_containers_list (&list, context->state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! json_gen_init (&gen, NULL))
    {
      ret = crun_make_error (err, 0, "cannot allocate json generator");
      goto exit;
    }

  json_gen_config (gen, json_gen_beautify, 1);
  json_gen_array_open (gen);

  for (it = list; it; it = it->next)
    {
      libcrun_container_status_t status;
      int running = 0;
      int pid;
      const char *container_status = NULL;

      ret = libcrun_read_container_status (&status, context->state_root, it->name, err);
      if (UNLIKELY (ret < 0))
        goto exit;

      pid = status.pid;

      ret = libcrun_get_container_state_string (it->name, &status, context->state_root, &container_status,
                                                &running, err);
      if (UNLIKELY (ret < 0))
        {
          libcrun_error_write_warning_and_release (stderr, &err);
          continue;
        }

      if (! running)
        pid = 0;

      json_gen_map_open (gen);
      json_gen_string (gen, "id", strlen ("id"));
      json_gen_string (gen, it->name, strlen (it->name));
      json_gen_string (gen, "pid", strlen ("pid"));
      map_int (gen, pid);
      json_gen_string (gen, "status", strlen ("status"));
      json_gen_string (gen, container_status, strlen (container_status));
      json_gen_string (gen, "bundle", strlen ("bundle"));
      json_gen_string (gen, status.bundle, strlen (status.bundle));
      json_gen_string (gen, "created", strlen ("created"));
      json_gen_string (gen, status.created, strlen (status.created));
      json_gen_string (gen, "owner", strlen ("owner"));
      json_gen_string (gen, status.owner, safe_strlen (status.owner));
      json_gen_map_close (gen);

      libcrun_free_container_status (&status);
    }

  json_gen_array_close (gen);
  if (json_gen_get_buf (gen, &content, &len) != json_gen_status_ok)
    {
      ret = libcrun_make_error (err, 0, "cannot generate json list");
      goto exit;
    }

  while (len)
    {
      size_t written = fwrite (content, 1, len, out);
      if (ferror (out))
        {
          ret = libcrun_make_error (err, errno, "error writing to file");
          goto exit;
        }
      len -= written;
      content += written;
    }

  ret = 0;

exit:
  if (list)
    libcrun_free_containers_list (list);
  if (gen)
    json_gen_free (gen);

  return ret;
}

int
libcrun_container_update_intel_rdt (libcrun_context_t *context, const char *id, struct libcrun_intel_rdt_update *update, libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container = NULL;
  int ret;

  ret = read_container_config_from_state (&container, context->state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_update_intel_rdt (id, container, update->l3_cache_schema, update->mem_bw_schema, update->schemata, err);
}

static int
libcrun_container_add_or_remove_mounts_from_file (libcrun_context_t *context, const char *id, const char *file, bool add, libcrun_error_t *err)
{
  cleanup_custom_handler_instance struct custom_handler_instance_s *custom_handler = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  cleanup_free runtime_spec_schema_defs_mount **mounts = NULL;
  const char *state_root = context->state_root;
  cleanup_free parser_error parser_err = NULL;
  struct parser_context pctx = { 0, stderr };
  libcrun_container_status_t status = {};
  cleanup_free char *content = NULL;
  json_object *doc = NULL;
  size_t n_mounts = 0, len, i;
  int ret = 1;

  ret = read_all_file (file, &content, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = parse_json_file (&doc, content, &pctx, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! json_object_is_type (doc, json_type_array))
    {
      ret = crun_make_error (err, 0, "mounts must be an array");
      goto cleanup;
    }
  else
    {
      n_mounts = json_object_array_length (doc);

      mounts = xmalloc0 ((n_mounts + 1) * sizeof (*mounts));
      for (i = 0; i < n_mounts; i++)
        {
          mounts[i] = make_runtime_spec_schema_defs_mount (json_object_array_get_idx (doc, i), &pctx, &parser_err);
          if (mounts[i] == NULL)
            {
              ret = crun_make_error (err, 0, "cannot parse mount: %s", parser_err);
              goto cleanup;
            }
        }
    }

  if (add)
    ret = libcrun_make_runtime_mounts (container, &status, mounts, n_mounts, err);
  else
    ret = libcrun_destroy_runtime_mounts (container, &status, mounts, n_mounts, err);

cleanup:
  if (doc)
    json_object_put (doc);
  if (mounts)
    for (i = 0; i < n_mounts; i++)
      free_runtime_spec_schema_defs_mount (mounts[i]);
  return ret;
}

int
libcrun_container_add_mounts_from_file (libcrun_context_t *context, const char *id, const char *file, libcrun_error_t *err)
{
  return libcrun_container_add_or_remove_mounts_from_file (context, id, file, true, err);
}

int
libcrun_container_remove_mounts_from_file (libcrun_context_t *context, const char *id, const char *file, libcrun_error_t *err)
{
  return libcrun_container_add_or_remove_mounts_from_file (context, id, file, false, err);
}
