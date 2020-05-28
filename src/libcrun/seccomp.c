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
#include "seccomp.h"
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
#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef __NR_seccomp
# define __NR_seccomp 0xffff //seccomp syscall number unknown for this architecture
#endif

#ifndef SECCOMP_SET_MODE_STRICT
# define SECCOMP_SET_MODE_STRICT 0
#endif

#ifndef SECCOMP_SET_MODE_FILTER
# define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
# define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif

#ifndef SECCOMP_FILTER_FLAG_LOG
# define SECCOMP_FILTER_FLAG_LOG (1UL << 1)
#endif

#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
# define SECCOMP_FILTER_FLAG_SPEC_ALLOW	(1UL << 2)
#endif

static int
syscall_seccomp (unsigned int operation, unsigned int flags, void *args)
{
  return (int) syscall (__NR_seccomp, operation, flags, args);
}

static unsigned long
get_seccomp_operator (const char *name, libcrun_error_t *err)
{
  if (strcmp (name, "SCMP_CMP_NE") == 0)
    return SCMP_CMP_NE;
  if (strcmp (name, "SCMP_CMP_LT") == 0)
    return SCMP_CMP_LT;
  if (strcmp (name, "SCMP_CMP_LE") == 0)
    return SCMP_CMP_LE;
  if (strcmp (name, "SCMP_CMP_EQ") == 0)
    return SCMP_CMP_EQ;
  if (strcmp (name, "SCMP_CMP_GE") == 0)
    return SCMP_CMP_GE;
  if (strcmp (name, "SCMP_CMP_GT") == 0)
    return SCMP_CMP_GT;
  if (strcmp (name, "SCMP_CMP_MASKED_EQ") == 0)
    return SCMP_CMP_MASKED_EQ;

  crun_make_error (err, 0, "seccomp get operator", name);
  return 0;
}

static unsigned long long
get_seccomp_action (const char *name, int errno_ret, libcrun_error_t *err)
{
  const char *p;

  p = name;
  if (strncmp (p, "SCMP_ACT_", 9))
    goto fail;

  p += 9;

  if (strcmp (p, "ALLOW") == 0)
    return SCMP_ACT_ALLOW;
  else if (strcmp (p, "ERRNO") == 0)
    return SCMP_ACT_ERRNO (errno_ret);
  else if (strcmp (p, "KILL") == 0)
    return SCMP_ACT_KILL;
  else if (strcmp (p, "TRAP") == 0)
    return SCMP_ACT_TRAP;
  else if (strcmp (p, "TRACE") == 0)
    return SCMP_ACT_TRACE (errno_ret);
#ifdef SCMP_ACT_KILL_PROCESS
  else if (strcmp (p, "KILL_PROCESS") == 0)
    return SCMP_ACT_KILL_PROCESS;
#endif
#ifdef SCMP_ACT_NOTIFY
  else if (strcmp (p, "NOTIFY") == 0)
    return SCMP_ACT_NOTIFY;
#endif

 fail:
  crun_make_error (err, 0, "seccomp get action", name);
  return 0;
}

static void
make_lowercase (char *str)
{
  while (*str)
    {
      *str = tolower (*str);
      str++;
    }
}

static void
cleanup_seccompp (void *p)
{
  scmp_filter_ctx *ctx = (void **) p;
  if (*ctx)
    seccomp_release (*ctx);
}
#define cleanup_seccomp __attribute__((cleanup (cleanup_seccompp)))

int
libcrun_apply_seccomp (int infd, int listener_receiver_fd, char **seccomp_flags, size_t seccomp_flags_len, libcrun_error_t *err)
{
  int ret;
  struct sock_fprog seccomp_filter;
  cleanup_free char *bpf = NULL;
  unsigned int flags = 0;
  size_t len;

  if (infd < 0)
    return 0;

  if (UNLIKELY (lseek (infd, 0, SEEK_SET) == (off_t) -1))
    return crun_make_error (err, errno, "lseek");


  /* if no seccomp flag was specified use a sane default.  */
  if (seccomp_flags == NULL)
    flags = SECCOMP_FILTER_FLAG_LOG|SECCOMP_FILTER_FLAG_SPEC_ALLOW;
  else
    {
      size_t i = 0;
      for (i = 0; i < seccomp_flags_len; i++)
        {
          if (strcmp (seccomp_flags[i], "SECCOMP_FILTER_FLAG_TSYNC") == 0)
              flags |= SECCOMP_FILTER_FLAG_TSYNC;
          else if (strcmp (seccomp_flags[i], "SECCOMP_FILTER_FLAG_SPEC_ALLOW") == 0)
            flags |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
          else if (strcmp (seccomp_flags[i], "SECCOMP_FILTER_FLAG_LOG") == 0)
            flags |= SECCOMP_FILTER_FLAG_LOG;
          else
            return crun_make_error (err, 0, "unknown seccomp option %s", seccomp_flags[i]);
        }
    }

  ret = read_all_fd (infd, "seccomp.bpf", &bpf, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  seccomp_filter.len = len / 8;
  seccomp_filter.filter = (struct sock_filter *) bpf;

  if (listener_receiver_fd >= 0)
    {
#ifdef SECCOMP_FILTER_FLAG_NEW_LISTENER
      flags |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
#else
      return crun_make_error (err, 0, "SECCOMP_FILTER_FLAG_NEW_LISTENER not supported");
#endif
    }

  ret = syscall_seccomp (SECCOMP_SET_MODE_FILTER, flags, &seccomp_filter);
  if (UNLIKELY (ret < 0))
    {
      /* If any of the flags is not supported, try again without specifying them:  */
      if (errno == EINVAL)
        ret = syscall_seccomp (SECCOMP_SET_MODE_FILTER, 0, &seccomp_filter);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "seccomp (SECCOMP_SET_MODE_FILTER)");
    }

  if (listener_receiver_fd >= 0)
    {
      int fd = ret;
      ret = send_fd_to_socket (listener_receiver_fd, fd, err);
      if (UNLIKELY (ret < 0))
        return crun_error_wrap (err, "send listener fd `%d` to receiver", fd);
    }
  return 0;
}

int
libcrun_generate_seccomp (libcrun_container_t *container, int outfd, unsigned int options, libcrun_error_t *err)
{
  runtime_spec_schema_config_linux_seccomp *seccomp = container->container_def->linux->seccomp;
  int ret;
  size_t i;
  cleanup_seccomp scmp_filter_ctx ctx = NULL;
  int action, default_action;
  const char *def_action = "SCMP_ACT_ALLOW";

  if (seccomp == NULL)
    return 0;

  /* seccomp not available.  */
  if (prctl (PR_GET_SECCOMP, 0, 0, 0, 0) < 0)
    return crun_make_error (err, errno, "prctl");

  if (seccomp->default_action != NULL)
    def_action = seccomp->default_action;

  default_action = get_seccomp_action (def_action, EPERM, err);
  if (UNLIKELY (err && *err != NULL))
    return crun_make_error (err, 0, "invalid seccomp action `%s`", seccomp->default_action);

  ctx = seccomp_init (default_action);
  if (ctx == NULL)
    return crun_make_error (err, 0, "error seccomp_init");

  for (i = 0; i < seccomp->architectures_len; i++)
    {
      uint32_t arch_token;
      const char *arch = seccomp->architectures[i];
      char lowercase_arch[32];

      if (has_prefix (arch, "SCMP_ARCH_"))
        arch += 10;
      stpncpy (lowercase_arch, arch, sizeof (lowercase_arch));
      make_lowercase (lowercase_arch);
#ifdef SECCOMP_ARCH_RESOLVE_NAME
      arch_token = seccomp_arch_resolve_name (lowercase_arch);
      if (arch_token == 0)
        return crun_make_error (err, -ret, "seccomp unknown architecture %s", arch);
#else
      arch_token = SCMP_ARCH_NATIVE;
#endif
      ret = seccomp_arch_add (ctx, arch_token);
      if (ret < 0 && ret != -EEXIST)
        return crun_make_error (err, -ret, "seccomp adding architecture");
    }

  for (i = 0; i < seccomp->syscalls_len; i++)
    {
      size_t j;
      int errno_ret = EPERM;

      if (seccomp->syscalls[i]->errno_ret_present)
        errno_ret = seccomp->syscalls[i]->errno_ret;

      action = get_seccomp_action (seccomp->syscalls[i]->action, errno_ret, err);
      if (UNLIKELY (err && *err != NULL))
        return crun_make_error (err, 0, "invalid seccomp action `%s`", seccomp->syscalls[i]->action);

      if (action == default_action)
        continue;

      for (j = 0; j < seccomp->syscalls[i]->names_len; j++)
        {
          int syscall = seccomp_syscall_resolve_name (seccomp->syscalls[i]->names[j]);

          if (UNLIKELY (syscall == __NR_SCMP_ERROR))
            {
              if (options & LIBCRUN_SECCOMP_FAIL_UNKNOWN_SYSCALL)
                return crun_make_error (err, 0, "invalid seccomp syscall `%s`", seccomp->syscalls[i]->names[j]);

              libcrun_warning ("unknown seccomp syscall `%s` ignored", seccomp->syscalls[i]->names[j]);
              continue;
            }

          if (seccomp->syscalls[i]->args == NULL)
            {
              ret = seccomp_rule_add (ctx, action, syscall, 0);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, -ret, "seccomp_rule_add `%s`", seccomp->syscalls[i]->names[j]);
            }
          else
            {
              size_t k;
              struct scmp_arg_cmp arg_cmp[6];
              bool multiple_args = false;
              uint32_t count[6] = {};

              for (k = 0; k < seccomp->syscalls[i]->args_len && k < 6; k++)
                {
                  uint32_t index;

                  index = seccomp->syscalls[i]->args[k]->index;
                  if (index >= 6)
                    return crun_make_error (err, 0, "invalid seccomp index %zu", i);

                  count[index]++;
                  if (count[index] > 1)
                    {
                      multiple_args = true;
                      break;
                    }
                }

              for (k = 0; k < seccomp->syscalls[i]->args_len && k < 6; k++)
                {
                  char *op = seccomp->syscalls[i]->args[k]->op;

                  arg_cmp[k].arg = seccomp->syscalls[i]->args[k]->index;
                  arg_cmp[k].op = get_seccomp_operator (op, err);
                  if (arg_cmp[k].op == 0)
                    return crun_make_error (err, 0, "get_seccomp_operator");
                  arg_cmp[k].datum_a = seccomp->syscalls[i]->args[k]->value;
                  arg_cmp[k].datum_b = seccomp->syscalls[i]->args[k]->value_two;
                }

              if (! multiple_args)
                {
                  ret = seccomp_rule_add_array (ctx,
                                                action,
                                                syscall,
                                                k,
                                                arg_cmp);
                  if (UNLIKELY (ret < 0))
                    return crun_make_error (err, -ret, "seccomp_rule_add_array");
                }
              else
                {
                  size_t r;

                  for (r = 0; r < k; r++)
                    {
                      ret = seccomp_rule_add_array (ctx,
                                                    action,
                                                    syscall,
                                                    1,
                                                    &arg_cmp[r]);
                      if (UNLIKELY (ret < 0))
                        return crun_make_error (err, -ret, "seccomp_rule_add_array");
                    }
                }
            }
        }
    }

  if (outfd >= 0)
    {
      ret = seccomp_export_bpf (ctx, outfd);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "seccomp_export_bpf");
    }

  return 0;
}
