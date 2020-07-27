/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <config.h>
#include <errno.h>

#if HAVE_SECCOMP_GET_NOTIF_SIZES
# include <seccomp.h>
# include <sys/ioctl.h>
# include <linux/seccomp.h>
# include <sys/sysmacros.h>
#endif

#ifdef HAVE_DLOPEN
# include <dlfcn.h>
#endif

#include "utils.h"
#include "seccomp_notify.h"

struct plugin
{
  void *handle;
  void *opaque;
#if HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES
  run_oci_seccomp_notify_handle_request_cb handle_request_cb;
#endif
};

struct seccomp_notify_context_s
{
  struct plugin *plugins;
  size_t n_plugins;

#if HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES
  struct seccomp_notif_resp *sresp;
  struct seccomp_notif *sreq;
  struct seccomp_notif_sizes sizes;
#endif
};

void
cleanup_seccomp_notify_pluginsp (void *p)
{
  struct seccomp_notify_context_s **pp = p;
  if (*pp)
    {
      libcrun_error_t tmp_err = NULL;
      libcrun_free_seccomp_notify_plugins (*pp, &tmp_err);
      crun_error_release (&tmp_err);
      *pp = NULL;
    }
}

#if HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES
static int
seccomp_syscall (unsigned int op, unsigned int flags, void *args)
{
  errno = 0;
  return syscall (__NR_seccomp, op, flags, args);
}
#endif

LIBCRUN_PUBLIC int
libcrun_load_seccomp_notify_plugins (struct seccomp_notify_context_s **out, const char *plugins, struct libcrun_load_seccomp_notify_conf_s *conf, libcrun_error_t *err)
{
#if HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES
  cleanup_seccomp_notify_context struct seccomp_notify_context_s *ctx = xmalloc0 (sizeof *ctx);
  cleanup_free char *b = NULL;
  char *it, *saveptr;
  size_t s;

  if (seccomp_syscall (SECCOMP_GET_NOTIF_SIZES, 0, &ctx->sizes) < 0)
    return crun_make_error (err, errno, "seccomp GET_NOTIF_SIZES");

  ctx->sreq = xmalloc (ctx->sizes.seccomp_notif);
  ctx->sresp = xmalloc (ctx->sizes.seccomp_notif_resp);

  ctx->n_plugins = 1;
  for (it = b; it; it = strchr (it, ':'))
    ctx->n_plugins++;

  ctx->plugins = xmalloc0 (sizeof (struct plugin) * (ctx->n_plugins + 1));

  b = xstrdup (plugins);
  for (s = 0, it = strtok_r (b, ":", &saveptr); it; s++, it = strtok_r (NULL, ":", &saveptr))
    {
      run_oci_seccomp_notify_plugin_version_cb version_cb;
      run_oci_seccomp_notify_start_cb start_cb;
      void *opq = NULL;

      ctx->plugins[s].handle = dlopen (it, RTLD_NOW);
      if (ctx->plugins[s].handle == NULL)
        return crun_make_error (err, 0, "cannot load `%s`: %s", it, dlerror ());

      version_cb = (run_oci_seccomp_notify_plugin_version_cb) dlsym (ctx->plugins[s].handle, "run_oci_seccomp_notify_version");
      if (version_cb != NULL)
        {
          int version;

          version = version_cb ();
          if (version != 1)
            return crun_make_error (err, ENOTSUP, "invalid version supported by the plugin `%s`", it);
        }

      ctx->plugins[s].handle_request_cb = (run_oci_seccomp_notify_handle_request_cb) dlsym (ctx->plugins[s].handle, "run_oci_seccomp_notify_handle_request");
      if (ctx->plugins[s].handle_request_cb == NULL)
        return crun_make_error (err, ENOTSUP, "plugin `%s` doesn't export `run_oci_seccomp_notify_handle_request`", it);

      start_cb = (run_oci_seccomp_notify_start_cb) dlsym (ctx->plugins[s].handle, "run_oci_seccomp_notify_start");
      if (start_cb)
        {
          int ret;

          ret = start_cb (&opq, conf, sizeof (*conf));
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, -ret, "error loading `%s`", it);
        }
      ctx->plugins[s].opaque = opq;
    }

  /* Change ownership.  */
  *out = ctx;
  ctx = NULL;
  return 0;
#else
  return crun_make_error (err, ENOTSUP, "seccomp notify support not available");
#endif
}

LIBCRUN_PUBLIC int
libcrun_seccomp_notify_plugins (struct seccomp_notify_context_s *ctx, int seccomp_fd, libcrun_error_t *err)
{
#if HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES
  size_t i;
  int ret;

  memset (ctx->sreq, 0, ctx->sizes.seccomp_notif);
  memset (ctx->sresp, 0, ctx->sizes.seccomp_notif_resp);

  ret = ioctl (seccomp_fd, SECCOMP_IOCTL_NOTIF_RECV, ctx->sreq);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "ioctl");

  for (i = 0; i < ctx->n_plugins; i++)
    {
      if (ctx->plugins[i].handle_request_cb)
        {
          int handled = 0;
          int ret;

          ret = ctx->plugins[i].handle_request_cb (ctx->plugins[i].opaque, &ctx->sizes, ctx->sreq, ctx->sresp, seccomp_fd, &handled);
          if (UNLIKELY (ret != 0))
            return crun_make_error (err, -ret, "error handling seccomp notify request");

          if (handled == RUN_OCI_SECCOMP_NOTIFY_HANDLE_SEND_RESPONSE)
            goto send_resp;

          /* The plugin will take care of it.  */
          if (handled == RUN_OCI_SECCOMP_NOTIFY_HANDLE_DELAYED_RESPONSE)
            return 0;
        }
    }

  /* No plugin could handle the request.  */
  ctx->sresp->error = -ENOTSUP;
  ctx->sresp->flags = 0;

 send_resp:
  ctx->sresp->id = ctx->sreq->id;
  ret = ioctl (seccomp_fd, SECCOMP_IOCTL_NOTIF_SEND, ctx->sresp);
  if (UNLIKELY (ret < 0))
    {
      if (errno == ENOENT)
        return 0;
      return crun_make_error (err, errno, "ioctl");
    }
  return 0;
#else
  return crun_make_error (err, ENOTSUP, "seccomp notify support not available");
#endif
}

LIBCRUN_PUBLIC int
libcrun_free_seccomp_notify_plugins (struct seccomp_notify_context_s *ctx, libcrun_error_t *err)
{
#if HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES
  size_t i;

  if (ctx == NULL)
    return crun_make_error (err, EINVAL, "invalid seccomp notify context");

  free (ctx->sreq);
  free (ctx->sresp);

  for (i = 0; i < ctx->n_plugins; i++)
    if (ctx->plugins && ctx->plugins[i].handle)
      {
        run_oci_seccomp_notify_stop_cb cb;

        cb = (run_oci_seccomp_notify_stop_cb) dlsym (ctx->plugins[i].handle, "run_oci_seccomp_notify_stop");
        if (cb)
          cb (ctx->plugins[i].opaque);
        dlclose (ctx->plugins[i].handle);
      }

  free (ctx);

  return 0;
#else
  return crun_make_error (err, ENOTSUP, "seccomp notify support not available");
#endif
}
