/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Adrian Reber <areber@redhat.com>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>

#include "crun.h"
#include "checkpoint.h"
#include "libcrun/container.h"
#include "libcrun/status.h"
#include "libcrun/utils.h"

enum
{
  OPTION_IMAGE_PATH = 1000,
  OPTION_WORK_PATH,
  OPTION_TCP_ESTABLISHED,
  OPTION_SHELL_JOB,
  OPTION_EXT_UNIX_SK,
  OPTION_PID_FILE,
  OPTION_CONSOLE_SOCKET,
  OPTION_FILE_LOCKS,
  OPTION_MANAGE_CGROUPS_MODE,
  OPTION_NETWORK_LOCK_METHOD,
  OPTION_LSM_PROFILE,
  OPTION_LSM_MOUNT_CONTEXT,
};

static char doc[] = "OCI runtime";

static const char *bundle = NULL;

static libcrun_context_t crun_context;

static libcrun_checkpoint_restore_t cr_options;

static struct argp_option options[]
    = { { "bundle", 'b', "DIR", 0, "container bundle (default \".\")", 0 },
        { "image-path", OPTION_IMAGE_PATH, "DIR", 0, "path for saving criu image files", 0 },
        { "work-path", OPTION_WORK_PATH, "DIR", 0, "path for saving work files and logs", 0 },
        { "tcp-established", OPTION_TCP_ESTABLISHED, 0, 0, "allow open tcp connections", 0 },
        { "ext-unix-sk", OPTION_EXT_UNIX_SK, 0, 0, "allow external unix sockets", 0 },
        { "shell-job", OPTION_SHELL_JOB, 0, 0, "allow shell jobs", 0 },
        { "detach", 'd', 0, 0, "detach from the container's process", 0 },
        { "pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container", 0 },
        { "console-socket", OPTION_CONSOLE_SOCKET, "SOCKET", 0,
          "path to a socket that will receive the ptmx end of the tty", 0 },
        { "file-locks", OPTION_FILE_LOCKS, 0, 0, "allow file locks", 0 },
        { "manage-cgroups-mode", OPTION_MANAGE_CGROUPS_MODE, "MODE", 0, "cgroups mode: 'soft' (default), 'ignore', 'full' and 'strict'", 0 },
        { "network-lock", OPTION_NETWORK_LOCK_METHOD, 0, 0, "set network lock method", 0 },
        { "lsm-profile", OPTION_LSM_PROFILE, "VALUE", 0, "Specify an LSM profile to be used during restore in the form of TYPE:NAME", 0 },
        { "lsm-mount-context", OPTION_LSM_MOUNT_CONTEXT, "VALUE", 0, "Specify an LSM mount context to be used during restore", 0 },
        {
            0,
        } };

static char args_doc[] = "restore CONTAINER";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case ARGP_KEY_NO_ARGS:
      libcrun_fail_with_error (0, "please specify a ID for the container");

    case OPTION_IMAGE_PATH:
      cr_options.image_path = argp_mandatory_argument (arg, state);
      break;

    case OPTION_WORK_PATH:
      cr_options.work_path = argp_mandatory_argument (arg, state);
      break;

    case 'b':
      bundle = argp_mandatory_argument (arg, state);
      break;

    case OPTION_TCP_ESTABLISHED:
      cr_options.tcp_established = true;
      break;

    case OPTION_EXT_UNIX_SK:
      cr_options.ext_unix_sk = true;
      break;

    case OPTION_SHELL_JOB:
      cr_options.shell_job = true;
      break;

    case OPTION_FILE_LOCKS:
      cr_options.file_locks = true;
      break;

    case 'd':
      cr_options.detach = true;
      break;

    case OPTION_CONSOLE_SOCKET:
      cr_options.console_socket = argp_mandatory_argument (arg, state);
      break;

    case OPTION_PID_FILE:
      crun_context.pid_file = argp_mandatory_argument (arg, state);
      break;

    case OPTION_MANAGE_CGROUPS_MODE:
      cr_options.manage_cgroups_mode = crun_parse_manage_cgroups_mode (argp_mandatory_argument (arg, state));
      break;

    case OPTION_NETWORK_LOCK_METHOD:
      cr_options.network_lock_method = crun_parse_network_lock_method (argp_mandatory_argument (arg, state));
      break;

    case OPTION_LSM_PROFILE:
      cr_options.lsm_profile = argp_mandatory_argument (arg, state);
      break;

    case OPTION_LSM_MOUNT_CONTEXT:
      cr_options.lsm_mount_context = argp_mandatory_argument (arg, state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int
crun_command_restore (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  cleanup_free char *bundle_cleanup = NULL;
  cleanup_free char *cr_path = NULL;
  int first_arg;
  int ret;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &cr_options);
  crun_assert_n_args (argc - first_arg, 1, 2);

  /* Make sure the bundle is an absolute path.  */

  if (bundle == NULL)
    {
      bundle = realpath (".", NULL);
    }
  else
    {
      if (bundle[0] != '/')
        {
          bundle_cleanup = realpath (bundle, NULL);
          if (bundle_cleanup == NULL)
            libcrun_fail_with_error (errno, "realpath `%s` failed", bundle);
          bundle = bundle_cleanup;
        }

      if (chdir (bundle) < 0)
        libcrun_fail_with_error (errno, "chdir `%s` failed", bundle);
    }

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (cr_options.image_path == NULL)
    {
      cleanup_free char *path = NULL;

      path = getcwd (NULL, 0);
      if (UNLIKELY (path == NULL))
        libcrun_fail_with_error (0, "realloc failed");

      ret = asprintf (&cr_path, "%s/checkpoint", path);
      if (UNLIKELY (ret < 0))
        OOM ();
      cr_options.image_path = cr_path;
    }

  crun_context.bundle = bundle;
  return libcrun_container_restore (&crun_context, argv[first_arg], &cr_options, err);
}
