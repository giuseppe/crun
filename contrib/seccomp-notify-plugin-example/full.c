/*
  A simple plugin that always returns ENOSPC.
*/

#include <stdlib.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <stdio.h>

struct libcrun_load_seccomp_notify_conf_s
{
  const char *runtime_root_path;
  const char *name;
  const char *bundle_path;
  const char *oci_config_path;
};

int
run_oci_seccomp_notify_start (void **opaque, struct libcrun_load_seccomp_notify_conf_s *conf, size_t size_configuration)
{
  if (size_configuration != sizeof (struct libcrun_load_seccomp_notify_conf_s))
    return -EINVAL;

  return 0;
}

int
run_oci_seccomp_notify_handle_request (void *opaque, struct seccomp_notif *sreq, struct seccomp_notif_resp *sresp, int seccomp_fd, int *handled)
{
  sresp->error = -ENOSPC;
  *handled = 1;
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
