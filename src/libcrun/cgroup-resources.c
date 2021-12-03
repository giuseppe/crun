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
#include "cgroup.h"
#include "cgroup-internal.h"
#include "cgroup-systemd.h"
#include "cgroup-utils.h"
#include "cgroup-resources.h"
#include "ebpf.h"
#include "utils.h"
#include "status.h"
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/vfs.h>
#include <inttypes.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>

static int
is_rwm (const char *str, libcrun_error_t *err)
{
  const char *it;
  bool r = false;
  bool w = false;
  bool m = false;

  for (it = str; *it; it++)
    switch (*it)
      {
      case 'r':
        r = true;
        break;

      case 'w':
        w = true;
        break;

      case 'm':
        m = true;
        break;

      default:
        return crun_make_error (err, 0, "invalid mode specified `%s`", str);
      }

  return r && w && m ? 1 : 0;
}

static int
check_cgroup_v2_controller_available_wrapper (int ret, int cgroup_dirfd, const char *name, libcrun_error_t *err)
{
  if (ret == 0 || err == NULL)
    return 0;

  errno = crun_error_get_errno (err);

  /* If the file is not found, try to give a more meaningful error message.  */
  if (errno == ENOENT || errno == EPERM || errno == EACCES)
    {
      cleanup_free char *controllers = NULL;
      libcrun_error_t tmp_err = NULL;
      cleanup_free char *key = NULL;
      char *saveptr = NULL;
      bool found = false;
      const char *token;
      char *it;

      /* Check if the specified controller is enabled.  */
      key = xstrdup (name);

      it = strchr (key, '.');
      if (it == NULL)
        {
          crun_error_release (err);
          return crun_make_error (err, 0, "the specified key has not the form CONTROLLER.VALUE `%s`", name);
        }
      *it = '\0';

      /* cgroup. files are not part of a controller.  Return the original error.  */
      if (strcmp (key, "cgroup") == 0)
        return ret;

      /* If the cgroup.controllers file cannot be read, return the original error.  */
      if (read_all_file_at (cgroup_dirfd, "cgroup.controllers", &controllers, NULL, &tmp_err) < 0)
        {
          crun_error_release (&tmp_err);
          return ret;
        }
      for (token = strtok_r (controllers, " \n", &saveptr); token; token = strtok_r (NULL, " \n", &saveptr))
        {
          if (strcmp (token, key) == 0)
            {
              found = true;
              break;
            }
        }
      if (! found)
        {
          crun_error_release (err);
          return crun_make_error (err, 0, "the requested cgroup controller `%s` is not available", key);
        }
    }
  return ret;
}

static int
write_file_and_check_controllers_at (bool cgroup2, int dirfd, const char *name, const void *data, size_t len,
                                     libcrun_error_t *err)
{
  int ret;

  ret = write_file_at (dirfd, name, data, len, err);
  if (cgroup2)
    return check_cgroup_v2_controller_available_wrapper (ret, dirfd, name, err);
  return ret;
}

/* The parser generates different structs but they are really all the same.  */
typedef runtime_spec_schema_defs_linux_block_io_device_throttle throttling_s;

static int
write_blkio_v1_resources_throttling (int dirfd, const char *name, throttling_s **throttling, size_t throttling_len,
                                     libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  cleanup_close int fd = -1;

  if (throttling == NULL)
    return 0;

  fd = openat (dirfd, name, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open `%s`", name);

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu64 "\n", throttling[i]->major, throttling[i]->minor,
                     throttling[i]->rate);

      ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write `%s`", name);
    }
  return 0;
}

static int
write_blkio_v2_resources_throttling (int fd, const char *name, throttling_s **throttling, size_t throttling_len,
                                     libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;

  if (throttling == NULL)
    return 0;

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %s=%" PRIu64 "\n", throttling[i]->major, throttling[i]->minor,
                     name, throttling[i]->rate);

      ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write `%s`", name);
    }
  return 0;
}

static int
write_blkio_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_block_io *blkio,
                       libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;

  if (blkio->weight)
    {
      uint32_t val = blkio->weight;

      len = sprintf (fmt_buf, "%" PRIu32, val);
      ret = write_file_at (dirfd, cgroup2 ? "io.bfq.weight" : "blkio.weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->leaf_weight)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set leaf_weight with cgroupv2");
      len = sprintf (fmt_buf, "%d", blkio->leaf_weight);
      ret = write_file_at (dirfd, "blkio.leaf_weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->weight_device_len)
    {
      if (cgroup2)
        {
          cleanup_close int wfd = -1;
          size_t i;

          wfd = openat (dirfd, "io.bfq.weight", O_WRONLY);
          if (UNLIKELY (wfd < 0))
            return crun_make_error (err, errno, "open io.weight");
          for (i = 0; i < blkio->weight_device_len; i++)
            {
              uint32_t w = blkio->weight_device[i]->weight;

              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %i\n", blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor, w);
              ret = TEMP_FAILURE_RETRY (write (wfd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write io.weight");

              /* Ignore blkio->weight_device[i]->leaf_weight.  */
            }
        }
      else
        {
          cleanup_close int w_device_fd = -1;
          cleanup_close int w_leafdevice_fd = -1;
          size_t i;

          w_device_fd = openat (dirfd, "blkio.weight_device", O_WRONLY);
          if (UNLIKELY (w_device_fd < 0))
            return crun_make_error (err, errno, "open blkio.weight_device");

          w_leafdevice_fd = openat (dirfd, "blkio.leaf_weight_device", O_WRONLY);
          if (UNLIKELY (w_leafdevice_fd < 0))
            return crun_make_error (err, errno, "open blkio.leaf_weight_device");

          for (i = 0; i < blkio->weight_device_len; i++)
            {
              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu16 "\n", blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor, blkio->weight_device[i]->weight);
              ret = TEMP_FAILURE_RETRY (write (w_device_fd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.weight_device");

              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu16 "\n", blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor, blkio->weight_device[i]->leaf_weight);
              ret = TEMP_FAILURE_RETRY (write (w_leafdevice_fd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.leaf_weight_device");
            }
        }
    }
  if (cgroup2)
    {
      cleanup_close int wfd = -1;
      const char *name = "io.max";

      wfd = openat (dirfd, name, O_WRONLY);
      if (UNLIKELY (wfd < 0))
        {
          ret = crun_make_error (err, errno, "open `%s`", name);
          return check_cgroup_v2_controller_available_wrapper (ret, dirfd, name, err);
        }

      ret = write_blkio_v2_resources_throttling (wfd, "rbps", (throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wbps", (throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "riops", (throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wiops", (throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_bps_device",
                                                 (throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_bps_device",
                                                 (throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_iops_device",
                                                 (throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_iops_device",
                                                 (throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_network_resources (int dirfd_netclass, int dirfd_netprio, runtime_spec_schema_config_linux_resources_network *net,
                         libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
  if (net->class_id)
    {
      len = sprintf (fmt_buf, "%d", net->class_id);
      ret = write_file_at (dirfd_netclass, "net_cls.classid", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (net->priorities_len)
    {
      size_t i;
      cleanup_close int fd = -1;
      fd = openat (dirfd_netprio, "net_prio.ifpriomap", O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open `net_prio.ifpriomap`");

      for (i = 0; i < net->priorities_len; i++)
        {
          len = sprintf (fmt_buf, "%s %d\n", net->priorities[i]->name, net->priorities[i]->priority);
          ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write net_prio.ifpriomap");
        }
    }

  return 0;
}

static int
write_hugetlb_resources (int dirfd, bool cgroup2,
                         runtime_spec_schema_config_linux_resources_hugepage_limits_element **htlb, size_t htlb_len,
                         libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  for (i = 0; i < htlb_len; i++)
    {
      cleanup_free char *filename = NULL;
      const char *suffix;
      size_t len;
      int ret;

      suffix = cgroup2 ? "max" : "limit_in_bytes";

      xasprintf (&filename, "hugetlb.%s.%s", htlb[i]->page_size, suffix);

      len = sprintf (fmt_buf, "%" PRIu64, htlb[i]->limit);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, filename, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_devices_resources_v1 (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                            libcrun_error_t *err)
{
  size_t i, len;
  int ret;
  char *default_devices[] = {
    "c *:* m",
    "b *:* m",
    "c 1:3 rwm",
    "c 1:8 rwm",
    "c 1:7 rwm",
    "c 5:0 rwm",
    "c 1:5 rwm",
    "c 1:9 rwm",
    "c 5:1 rwm",
    "c 136:* rwm",
    "c 5:2 rwm",
    "c 10:200 rwm",
    NULL
  };

  for (i = 0; i < devs_len; i++)
    {
      /* It is plenty of room for "TYPE MAJOR:MINOR ACCESS", where type is one char, and ACCESS is at most 3.   */
#define FMT_BUF_LEN 64
      char fmt_buf[FMT_BUF_LEN];
      const char *file = devs[i]->allow ? "devices.allow" : "devices.deny";

      if (devs[i]->type == NULL || devs[i]->type[0] == 'a')
        {
          strcpy (fmt_buf, "a");
          len = 1;
        }
      else
        {
          char fmt_buf_major[16];
          char fmt_buf_minor[16];

#define FMT_DEV(x, b)               \
  do                                \
    {                               \
      if (x##_present)              \
        sprintf (b, "%" PRIi64, x); \
      else                          \
        strcpy (b, "*");            \
  } while (0)

          FMT_DEV (devs[i]->major, fmt_buf_major);
          FMT_DEV (devs[i]->minor, fmt_buf_minor);

          len = snprintf (fmt_buf, FMT_BUF_LEN - 1, "%s %s:%s %s", devs[i]->type, fmt_buf_major, fmt_buf_minor,
                          devs[i]->access);
          /* Make sure it is still a NUL terminated string.  */
          fmt_buf[len] = '\0';
        }
      ret = write_file_at (dirfd, file, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (i = 0; default_devices[i]; i++)
    {
      ret = write_file_at (dirfd, "devices.allow", default_devices[i], strlen (default_devices[i]), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_devices_resources_v2_internal (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                                     libcrun_error_t *err)
{
  int i, ret;
  cleanup_free struct bpf_program *program = NULL;
  struct default_dev_s
  {
    char type;
    int major;
    int minor;
    const char *access;
  };
  struct default_dev_s default_devices[] = {
    { 'c', -1, -1, "m" },
    { 'b', -1, -1, "m" },
    { 'c', 1, 3, "rwm" },
    { 'c', 1, 8, "rwm" },
    { 'c', 1, 7, "rwm" },
    { 'c', 5, 0, "rwm" },
    { 'c', 1, 5, "rwm" },
    { 'c', 1, 9, "rwm" },
    { 'c', 5, 1, "rwm" },
    { 'c', 136, -1, "rwm" },
    { 'c', 5, 2, "rwm" },
    { 'c', 10, 200, "rwm" },
  };

  program = bpf_program_new (2048);

  program = bpf_program_init_dev (program, err);
  if (UNLIKELY (program == NULL))
    return -1;

  for (i = (sizeof (default_devices) / sizeof (default_devices[0])) - 1; i >= 0; i--)
    {
      program = bpf_program_append_dev (program, default_devices[i].access, default_devices[i].type,
                                        default_devices[i].major, default_devices[i].minor, true, err);
      if (UNLIKELY (program == NULL))
        return -1;
    }
  for (i = devs_len - 1; i >= 0; i--)
    {
      char type = 'a';
      int minor = -1, major = -1;
      if (devs[i]->type != NULL)
        type = devs[i]->type[0];

      if (devs[i]->major_present)
        major = devs[i]->major;
      if (devs[i]->minor_present)
        minor = devs[i]->minor;

      program = bpf_program_append_dev (program, devs[i]->access, type, major, minor, devs[i]->allow, err);
      if (UNLIKELY (program == NULL))
        return -1;
    }

  program = bpf_program_complete_dev (program, err);
  if (UNLIKELY (program == NULL))
    return -1;

  ret = libcrun_ebpf_load (program, dirfd, NULL, err);
  if (ret < 0)
    return ret;

  return 0;
}

static int
write_devices_resources_v2 (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                            libcrun_error_t *err)
{
  int ret;
  size_t i;
  bool can_skip = true;

  ret = write_devices_resources_v2_internal (dirfd, devs, devs_len, err);
  if (LIKELY (ret == 0))
    return 0;

  /* If writing the resources ebpf failed, check if it is fine to ignore the error.  */
  for (i = 0; i < devs_len; i++)
    {
      if (devs[i]->allow_present && ! devs[i]->allow)
        {
          can_skip = false;
          break;
        }
    }

  if (! can_skip)
    {
      libcrun_error_t tmp_err = NULL;
      int rootless;

      rootless = is_rootless (&tmp_err);
      if (UNLIKELY (rootless < 0))
        {
          crun_error_release (err);
          *err = tmp_err;
          return ret;
        }
      if (rootless)
        can_skip = true;
    }

  if (can_skip)
    {
      crun_error_release (err);
      ret = 0;
    }

  return ret;
}

static int
write_devices_resources (int dirfd, bool cgroup2, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                         libcrun_error_t *err)
{
  int ret;

  if (cgroup2)
    ret = write_devices_resources_v2 (dirfd, devs, devs_len, err);
  else
    ret = write_devices_resources_v1 (dirfd, devs, devs_len, err);
  if (UNLIKELY (ret < 0))
    {
      libcrun_error_t tmp_err = NULL;
      int rootless;

      rootless = is_rootless (&tmp_err);
      if (UNLIKELY (rootless < 0))
        {
          crun_error_release (&tmp_err);
          return ret;
        }

      if (rootless)
        {
          crun_error_release (err);
          ret = 0;
        }
    }
  return ret;
}

/* use for cgroupv2 files with .min, .max, .low, or .high suffix */
static int
cg_itoa (char *buf, int64_t value, bool cgroup2)
{
  if (! (cgroup2 && value == -1))
    return sprintf (buf, "%" PRIi64, value);

  memcpy (buf, "max", 4);
  return 3;
}

static int
write_memory (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory, libcrun_error_t *err)
{
  char limit_buf[32];
  size_t limit_buf_len;

  if (! memory->limit_present)
    return 0;

  limit_buf_len = cg_itoa (limit_buf, memory->limit, cgroup2);

  return write_file_at (dirfd, cgroup2 ? "memory.max" : "memory.limit_in_bytes", limit_buf, limit_buf_len, err);
}

static int
write_memory_swap (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory,
                   libcrun_error_t *err)
{
  int64_t swap;
  char swap_buf[32];
  size_t swap_buf_len;

  if (! memory->swap_present)
    return 0;

  swap = memory->swap;
  if (cgroup2 && memory->swap != -1)
    {
      if (! memory->limit_present)
        return crun_make_error (err, 0, "cannot set swap limit without the memory limit");
      if (memory->swap < memory->limit)
        return crun_make_error (err, 0, "cannot set memory+swap limit less than the memory limit");

      swap -= memory->limit;
    }

  swap_buf_len = cg_itoa (swap_buf, swap, cgroup2);

  return write_file_and_check_controllers_at (
      cgroup2, dirfd, cgroup2 ? "memory.swap.max" : "memory.memsw.limit_in_bytes", swap_buf, swap_buf_len, err);
}

static int
write_memory_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory,
                        libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[32];
  bool memory_limits_written = false;

  if (memory->limit_present)
    {
      ret = write_memory (dirfd, cgroup2, memory, err);
      if (ret >= 0)
        memory_limits_written = true;
      else
        {
          if (cgroup2 || crun_error_get_errno (err) != EINVAL)
            return ret;

          /*
            If we get an EINVAL error on cgroup v1 we reverse
            the order we write the memory limit and the swap.
            Attempt to write again the memory limit once the memory
            swap is written.
          */
          crun_error_release (err);
        }
    }

  ret = write_memory_swap (dirfd, cgroup2, memory, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (memory->limit_present && ! memory_limits_written)
    {
      ret = write_memory (dirfd, cgroup2, memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->kernel_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set kernel memory with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->kernel);
      ret = write_file_at (dirfd, "memory.kmem.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  // allows users set use_hierarchy as 0 when defined as false in spec.
  // if use_hierarchy is not defined in spec value defaults to 1 (True).
  // Note: users can only toggle use_hierarchy if the parent cgroup has use_hierarchy configured as 0.
  if (memory->use_hierarchy_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set useHierarchy memory with cgroupv2");

      ret = write_file_at (dirfd, "memory.use_hierarchy", (memory->use_hierarchy) ? "1" : "0", 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->reservation_present)
    {
      len = sprintf (fmt_buf, "%" PRIu64, memory->reservation);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, cgroup2 ? "memory.low" : "memory.soft_limit_in_bytes",
                                                 fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->disable_oom_killer)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot disable OOM killer with cgroupv2");

      ret = write_file_at (dirfd, "memory.oom_control", "1", 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->kernel_tcp_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set kernel TCP with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->kernel_tcp);
      ret = write_file_at (dirfd, "memory.kmem.tcp.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->swappiness_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set memory swappiness with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->swappiness);
      ret = write_file_at (dirfd, "memory.swappiness", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_pids_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_pids *pids,
                      libcrun_error_t *err)
{
  if (pids->limit)
    {
      char fmt_buf[32];
      size_t len;
      int ret;

      len = cg_itoa (fmt_buf, pids->limit, cgroup2);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, "pids.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_cpu_resources (int dirfd_cpu, bool cgroup2, runtime_spec_schema_config_linux_resources_cpu *cpu,
                     libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[64];
  int64_t period = -1;
  int64_t quota = -1;

  /* convert linearly from 2-262144 to 1-10000.  */
#define CONVERT_SHARES_TO_CGROUPS_V2(x) (1 + (((x) -2) * 9999) / 262142)

  if (cpu->shares)
    {
      uint32_t val = cpu->shares;

      if (cgroup2)
        val = CONVERT_SHARES_TO_CGROUPS_V2 (val);

      len = sprintf (fmt_buf, "%u", val);

      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpu, cgroup2 ? "cpu.weight" : "cpu.shares", fmt_buf,
                                                 len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->period)
    {
      if (cgroup2)
        period = cpu->period;
      else
        {
          len = sprintf (fmt_buf, "%" PRIu64, cpu->period);
          ret = write_file_at (dirfd_cpu, "cpu.cfs_period_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (cpu->quota)
    {
      if (cgroup2)
        quota = cpu->quota;
      else
        {
          len = sprintf (fmt_buf, "%" PRIu64, cpu->quota);
          ret = write_file_at (dirfd_cpu, "cpu.cfs_quota_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (cpu->realtime_period)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "realtime period not supported on cgroupv2");
      len = sprintf (fmt_buf, "%" PRIu64, cpu->realtime_period);
      ret = write_file_at (dirfd_cpu, "cpu.rt_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->realtime_runtime)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "realtime runtime not supported on cgroupv2");
      len = sprintf (fmt_buf, "%" PRIu64, cpu->realtime_runtime);
      ret = write_file_at (dirfd_cpu, "cpu.rt_runtime_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (cgroup2 && (quota > 0 || period > 0))
    {
      if (period < 0)
        period = 100000;
      if (quota < 0)
        len = sprintf (fmt_buf, "max %" PRIi64, period);
      else
        len = sprintf (fmt_buf, "%" PRIi64 " %" PRIi64, quota, period);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpu, "cpu.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_cpuset_resources (int dirfd_cpuset, int cgroup2, runtime_spec_schema_config_linux_resources_cpu *cpu,
                        libcrun_error_t *err)
{
  int ret;

  if (cpu->cpus)
    {
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpuset, "cpuset.cpus", cpu->cpus, strlen (cpu->cpus),
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->mems)
    {
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpuset, "cpuset.mems", cpu->mems, strlen (cpu->mems),
                                                 err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
update_cgroup_v1_resources (runtime_spec_schema_config_linux_resources *resources, const char *path, libcrun_error_t *err)
{
  int ret;

  if (resources->block_io)
    {
      cleanup_free char *path_to_blkio = NULL;
      cleanup_close int dirfd_blkio = -1;
      runtime_spec_schema_config_linux_resources_block_io *blkio = resources->block_io;

      ret = append_paths (&path_to_blkio, err, CGROUP_ROOT "/blkio", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_blkio = open (path_to_blkio, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_blkio < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_blkio);

      ret = write_blkio_resources (dirfd_blkio, false, blkio, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->network)
    {
      cleanup_free char *path_to_netclass = NULL;
      cleanup_close int dirfd_netclass = -1;
      cleanup_free char *path_to_netprio = NULL;
      cleanup_close int dirfd_netprio = -1;
      runtime_spec_schema_config_linux_resources_network *network = resources->network;

      ret = append_paths (&path_to_netclass, err, CGROUP_ROOT "/net_cls", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&path_to_netprio, err, CGROUP_ROOT "/net_prio", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_netclass = open (path_to_netclass, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_netclass < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_netclass);

      dirfd_netprio = open (path_to_netprio, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_netprio < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_netprio);

      ret = write_network_resources (dirfd_netclass, dirfd_netprio, network, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->hugepage_limits_len)
    {
      cleanup_free char *path_to_htlb = NULL;
      cleanup_close int dirfd_htlb = -1;

      ret = append_paths (&path_to_htlb, err, CGROUP_ROOT "/hugetlb", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      dirfd_htlb = open (path_to_htlb, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_htlb < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_htlb);

      ret = write_hugetlb_resources (dirfd_htlb, false, resources->hugepage_limits, resources->hugepage_limits_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->devices_len)
    {
      cleanup_free char *path_to_devs = NULL;
      cleanup_close int dirfd_devs = -1;

      ret = append_paths (&path_to_devs, err, CGROUP_ROOT "/devices", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_devs = open (path_to_devs, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_devs < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_devs);

      ret = write_devices_resources (dirfd_devs, false, resources->devices, resources->devices_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      cleanup_free char *path_to_mem = NULL;
      cleanup_close int dirfd_mem = -1;

      ret = append_paths (&path_to_mem, err, CGROUP_ROOT "/memory", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_mem = open (path_to_mem, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_mem < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_mem);

      ret = write_memory_resources (dirfd_mem, false, resources->memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->pids)
    {
      cleanup_free char *path_to_pid = NULL;
      cleanup_close int dirfd_pid = -1;

      ret = append_paths (&path_to_pid, err, CGROUP_ROOT "/pids", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_pid = open (path_to_pid, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_pid < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_pid);

      ret = write_pids_resources (dirfd_pid, false, resources->pids, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->cpu)
    {
      cleanup_free char *path_to_cpu = NULL;
      cleanup_close int dirfd_cpu = -1;
      cleanup_free char *path_to_cpuset = NULL;
      cleanup_close int dirfd_cpuset = -1;

      ret = append_paths (&path_to_cpu, err, CGROUP_ROOT "/cpu", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_cpu = open (path_to_cpu, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpu < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_cpu);
      ret = write_cpu_resources (dirfd_cpu, false, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (resources->cpu->cpus == NULL && resources->cpu->mems == NULL)
        return 0;

      ret = append_paths (&path_to_cpuset, err, CGROUP_ROOT "/cpuset", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_cpuset = open (path_to_cpuset, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpuset < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_cpuset);

      ret = write_cpuset_resources (dirfd_cpuset, false, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->unified && resources->unified->len > 0)
    return crun_make_error (err, 0, "invalid configuration: cannot use unified on cgroup v1");

  return 0;
}

static int
write_unified_resources (int cgroup_dirfd, runtime_spec_schema_config_linux_resources *resources, libcrun_error_t *err)
{
  size_t i;
  int ret;

  for (i = 0; i < resources->unified->len; i++)
    {
      size_t len;

      if (strchr (resources->unified->keys[i], '/'))
        return crun_make_error (err, 0, "key `%s` must be a file name without any slash", resources->unified->keys[i]);

      len = strlen (resources->unified->values[i]);
      ret = write_file_and_check_controllers_at (true, cgroup_dirfd, resources->unified->keys[i],
                                                 resources->unified->values[i], len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
update_cgroup_v2_resources (runtime_spec_schema_config_linux_resources *resources, const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int cgroup_dirfd = -1;
  int ret;

  if (resources->network)
    return crun_make_error (err, 0, "network limits not supported on cgroupv2");

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  cgroup_dirfd = open (cgroup_path, O_DIRECTORY);
  if (UNLIKELY (cgroup_dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", cgroup_path);

  if (resources->devices_len)
    {
      ret = write_devices_resources (cgroup_dirfd, true, resources->devices, resources->devices_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      ret = write_memory_resources (cgroup_dirfd, true, resources->memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->pids)
    {
      ret = write_pids_resources (cgroup_dirfd, true, resources->pids, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->cpu)
    {
      ret = write_cpu_resources (cgroup_dirfd, true, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_cpuset_resources (cgroup_dirfd, true, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->block_io)
    {
      ret = write_blkio_resources (cgroup_dirfd, true, resources->block_io, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->hugepage_limits_len)
    {
      ret = write_hugetlb_resources (cgroup_dirfd, true, resources->hugepage_limits, resources->hugepage_limits_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Write unified resources if any.  They have higher precedence and override any previous setting.  */
  if (resources->unified)
    {
      ret = write_unified_resources (cgroup_dirfd, resources, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

int
update_cgroup_resources (const char *path,
                         runtime_spec_schema_config_linux_resources *resources,
                         libcrun_error_t *err)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (path == NULL)
    {
      size_t i;

      if (resources->block_io || resources->network || resources->hugepage_limits_len || resources->memory
          || resources->pids || resources->cpu)
        return crun_make_error (err, 0, "cannot set limits without cgroups");

      for (i = 0; i < resources->devices_len; i++)
        {
          int rwm;

          rwm = is_rwm (resources->devices[i]->access, err);
          if (UNLIKELY (rwm < 0))
            return rwm;

          if (rwm == 0)
            return crun_make_error (err, 0, "cannot set limits without cgroups");
        }

      return 0;
    }
  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      return update_cgroup_v2_resources (resources, path, err);

    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      return update_cgroup_v1_resources (resources, path, err);

    default:
      return crun_make_error (err, 0, "invalid cgroup mode %d", cgroup_mode);
    }
}
