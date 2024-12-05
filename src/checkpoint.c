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
#if HAVE_CRIU && HAVE_DLOPEN
#  include <criu/criu.h>
#endif

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/status.h"
#include "libcrun/utils.h"

enum
{
  OPTION_IMAGE_PATH = 1000,
  OPTION_WORK_PATH,
  OPTION_LEAVE_RUNNING,
  OPTION_TCP_ESTABLISHED,
  OPTION_SHELL_JOB,
  OPTION_EXT_UNIX_SK,
  OPTION_FILE_LOCKS,
  OPTION_NETWORK_LOCK_METHOD,
  OPTION_PARENT_PATH,
  OPTION_PRE_DUMP,
  OPTION_MANAGE_CGROUPS_MODE,
};

static char doc[] = "OCI runtime";

static libcrun_checkpoint_restore_t cr_options;

static struct argp_option options[]
    = { { "image-path", OPTION_IMAGE_PATH, "DIR", 0, "path for saving criu image files", 0 },
        { "work-path", OPTION_WORK_PATH, "DIR", 0, "path for saving work files and logs", 0 },
        { "leave-running", OPTION_LEAVE_RUNNING, 0, 0, "leave the process running after checkpointing", 0 },
        { "tcp-established", OPTION_TCP_ESTABLISHED, 0, 0, "allow open tcp connections", 0 },
        { "ext-unix-sk", OPTION_EXT_UNIX_SK, 0, 0, "allow external unix sockets", 0 },
        { "shell-job", OPTION_SHELL_JOB, 0, 0, "allow shell jobs", 0 },
        { "file-locks", OPTION_FILE_LOCKS, 0, 0, "allow file locks", 0 },
        { "network-lock", OPTION_NETWORK_LOCK_METHOD, 0, 0, "set network lock method", 0 },
#ifdef CRIU_PRE_DUMP_SUPPORT
        { "parent-path", OPTION_PARENT_PATH, "DIR", 0, "path for previous criu image files in pre-dump", 0 },
        { "pre-dump", OPTION_PRE_DUMP, 0, 0, "dump container's memory information only, leave the container running after this", 0 },
#endif
        { "manage-cgroups-mode", OPTION_MANAGE_CGROUPS_MODE, "MODE", 0, "cgroups mode: 'soft' (default), 'ignore', 'full' and 'strict'", 0 },
        {
            0,
        } };

static char args_doc[] = "checkpoint CONTAINER";

int
crun_parse_network_lock_method (char *param arg_unused)
{
#if HAVE_CRIU && HAVE_DLOPEN & CRIU_NETWORK_LOCK
  if (strcmp (param, "iptables") == 0)
    return CRIU_NETWORK_LOCK_IPTABLES;
  else if (strcmp (param, "nftables") == 0)
    return CRIU_NETWORK_LOCK_NFTABLES;
  else if (strcmp (param, "skip") == 0)
    return CRIU_NETWORK_LOCK_SKIP;
  else
    libcrun_fail_with_error (0, "unknown network lock method specified");
#else
  return 0;
#endif
}

int
crun_parse_manage_cgroups_mode (char *param arg_unused)
{
#if HAVE_CRIU && HAVE_DLOPEN
  if (strcmp (param, "soft") == 0)
    return CRIU_CG_MODE_SOFT;
  else if (strcmp (param, "ignore") == 0)
    return CRIU_CG_MODE_IGNORE;
  else if (strcmp (param, "full") == 0)
    return CRIU_CG_MODE_FULL;
  else if (strcmp (param, "strict") == 0)
    return CRIU_CG_MODE_STRICT;
  else
    libcrun_fail_with_error (0, "unknown cgroup mode specified");
#else
  return 0;
#endif
}

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

    case OPTION_PARENT_PATH:
      cr_options.parent_path = argp_mandatory_argument (arg, state);
      break;

    case OPTION_PRE_DUMP:
      cr_options.pre_dump = true;
      break;

    case OPTION_LEAVE_RUNNING:
      cr_options.leave_running = true;
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

    case OPTION_MANAGE_CGROUPS_MODE:
      cr_options.manage_cgroups_mode = crun_parse_manage_cgroups_mode (argp_mandatory_argument (arg, state));
      break;

    case OPTION_NETWORK_LOCK_METHOD:
      cr_options.network_lock_method = crun_parse_network_lock_method (argp_mandatory_argument (arg, state));
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int
crun_command_checkpoint (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  cleanup_free char *cr_path = NULL;
  int first_arg;
  int ret;

  libcrun_context_t crun_context = {
    0,
  };

  cr_options.manage_cgroups_mode = -1;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &cr_options);
  crun_assert_n_args (argc - first_arg, 1, 2);

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

  return libcrun_container_checkpoint (&crun_context, argv[first_arg], &cr_options, err);
}
