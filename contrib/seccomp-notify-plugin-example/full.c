/*
  A simple plugin that always returns ENOSPC.
  It handles the notification in an async way.  Spawning a thread for each request.
*/

#include <stdlib.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../../src/libcrun/seccomp_notify_plugin.h"

struct args_s
{
  uint64_t id;
  int seccomp_fd;
  struct seccomp_notif_resp *resp;
};

static void *
start_routine (void *arg)
{
  struct args_s *args = arg;
  int ret;

  /* Pretend we are busy.  */
  sleep (3);

  args->resp->id = args->id;
  args->resp->error = -ENOSPC;
  args->resp->flags = 0;

  ret = ioctl (args->seccomp_fd, SECCOMP_IOCTL_NOTIF_SEND, args->resp);
  if (ret < 0)
    abort ();

  free (args->resp);
  free (args);

  return NULL;
}

static int
handle_async (struct seccomp_notif_sizes *sizes, struct seccomp_notif *sreq, int seccomp_fd)
{
  /* On errors we leak memory, but anyway we return the error and the watcher is terminated immediately.  */
  pthread_t thread;
  struct args_s *args;
  pthread_attr_t attr;

  args = malloc (sizeof (*args));
  if (args == NULL)
    return -errno;

  args->resp = malloc (sizes->seccomp_notif_resp);
  if (args->resp == NULL)
    return -errno;

  args->id = sreq->id;
  args->seccomp_fd = seccomp_fd;

  if (pthread_attr_init (&attr) < 0)
    return -errno;

  if (pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED) < 0)
    return -errno;

  if (pthread_create (&thread, &attr, start_routine, args) < 0)
    return -errno;

  if (pthread_attr_destroy (&attr) < 0)
    return -errno;

  return 0;
}

int
run_oci_seccomp_notify_start (void **opaque, struct libcrun_load_seccomp_notify_conf_s *conf, size_t size_configuration)
{
  if (size_configuration != sizeof (struct libcrun_load_seccomp_notify_conf_s))
    return -EINVAL;

  return 0;
}

int
run_oci_seccomp_notify_handle_request (void *opaque, struct seccomp_notif_sizes *sizes, struct seccomp_notif *sreq, struct seccomp_notif_resp *sresp, int seccomp_fd, int *handled)
{
  int ret;

  ret = handle_async (sizes, sreq, seccomp_fd);
  if (ret < 0)
    return ret;

  *handled = RUN_OCI_SECCOMP_NOTIFY_HANDLE_DELAYED_RESPONSE;
  return 0;
}

int
run_oci_seccomp_notify_stop (void *opaque)
{
  return 0;
}

int
run_oci_seccomp_notify_plugin_version ()
{
  return 1;
}
