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
#include "ebpf.h"
#include "utils.h"
#include "status.h"
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/vfs.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>

#ifdef HAVE_SYSTEMD
#  include <systemd/sd-bus.h>

#  define SYSTEMD_PROPERTY_PREFIX "org.systemd.property."

static void
get_systemd_scope_and_slice (const char *id, const char *cgroup_path, char **scope, char **slice)
{
  char *n;

  if (cgroup_path == NULL || cgroup_path[0] == '\0')
    {
      xasprintf (scope, "crun-%s.scope", id);
      return;
    }

  n = strchr (cgroup_path, ':');
  if (n == NULL)
    xasprintf (scope, "%s.scope", cgroup_path);
  else
    {
      xasprintf (scope, "%s.scope", n + 1);
      n = strchr (*scope, ':');
      if (n)
        *n = '-';
    }
  if (slice)
    {
      *slice = xstrdup (cgroup_path);
      n = strchr (*slice, ':');
      if (n)
        *n = '\0';
    }
}

/* set the rt-runtime for the current cgroup and its parent if the path is not a scope.  */
static int
setup_rt_runtime (runtime_spec_schema_config_linux_resources *resources,
                  const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int dirfd = -1;
  bool need_set_parent = true;
  char fmt_buf[64];
  size_t len;
  int ret;

  if (resources == NULL || resources->cpu == NULL)
    return 0;

  if (has_suffix (path, ".scope"))
    need_set_parent = false;

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, "cpu", path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  dirfd = open (cgroup_path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", cgroup_path);

  if (resources->cpu->realtime_period)
    {
      len = sprintf (fmt_buf, "%" PRIu64, resources->cpu->realtime_period);

      if (need_set_parent)
        {
          ret = write_file_at_with_flags (dirfd, O_WRONLY, 0, "../cpu.rt_period_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = write_file_at_with_flags (dirfd, O_WRONLY, 0, "cpu.rt_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->cpu->realtime_runtime)
    {
      len = sprintf (fmt_buf, "%" PRIu64, resources->cpu->realtime_runtime);

      if (need_set_parent)
        {
          ret = write_file_at_with_flags (dirfd, O_WRONLY, 0, "../cpu.rt_runtime_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = write_file_at_with_flags (dirfd, O_WRONLY, 0, "cpu.rt_runtime_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
systemd_finalize (struct libcrun_cgroup_args *args, char **path_out,
                  int cgroup_mode, const char *suffix, libcrun_error_t *err)
{
  runtime_spec_schema_config_linux_resources *resources = args->resources;
  cleanup_free char *cgroup_path = NULL;
  cleanup_free char *content = NULL;
  cleanup_free char *path = NULL;
  pid_t pid = args->pid;
  int ret;
  char *from, *to;
  char *saveptr = NULL;

  xasprintf (&cgroup_path, "/proc/%d/cgroup", pid);
  ret = read_all_file (cgroup_path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  switch (cgroup_mode)
    {
    case CGROUP_MODE_HYBRID:
    case CGROUP_MODE_LEGACY:
      from = strstr (content, ":memory:");
      if (LIKELY (from != NULL))
        from += 8;
      else
        {
          from = strstr (content, ":pids:");
          if (UNLIKELY (from == NULL))
            return crun_make_error (err, 0, "cannot find memory or pids controller for the current process");

          from += 6;
        }

      to = strchr (from, '\n');
      if (UNLIKELY (to == NULL))
        return crun_make_error (err, 0, "cannot parse `%s`", PROC_SELF_CGROUP);
      *to = '\0';
      if (suffix == NULL)
        path = xstrdup (from);
      else
        {
          ret = append_paths (&path, err, from, suffix, NULL);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      *to = '\n';

      if (geteuid ())
        return 0;

      for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
        {
          char *subpath, *subsystem;
          subsystem = strchr (from, ':') + 1;
          subpath = strchr (subsystem, ':') + 1;
          *(subpath - 1) = '\0';

          if (subsystem[0] == '\0')
            {
              if (cgroup_mode == CGROUP_MODE_LEGACY)
                continue;

              subsystem = "unified";
            }

          if (strcmp (subpath, path))
            {
              ret = enter_cgroup_subsystem (pid, subsystem, path, true, err);
              if (UNLIKELY (ret < 0))
                {
                  /* If it is a named hierarchy, skip the error.  */
                  if (strchr (subsystem, '='))
                    {
                      crun_error_release (err);
                      continue;
                    }
                  return ret;
                }
            }
        }

      ret = setup_rt_runtime (resources, path, err);
      if (UNLIKELY (ret < 0))
        return ret;

      break;

    case CGROUP_MODE_UNIFIED:
      {
        cleanup_free char *dir = NULL;

        from = strstr (content, "0::");
        if (UNLIKELY (from == NULL))
          return crun_make_error (err, 0, "cannot find cgroup2 for the current process");

        from += 3;
        to = strchr (from, '\n');
        if (UNLIKELY (to == NULL))
          return crun_make_error (err, 0, "cannot parse `%s`", PROC_SELF_CGROUP);
        *to = '\0';
        if (suffix == NULL)
          path = xstrdup (from);
        else
          {
            ret = append_paths (&path, err, from, suffix, NULL);
            if (UNLIKELY (ret < 0))
              return ret;
          }
        *to = '\n';

        ret = append_paths (&dir, err, CGROUP_ROOT, path, NULL);
        if (UNLIKELY (ret < 0))
          return ret;

        /* On cgroup v2, processes can be only in leaf nodes.  If a suffix is used,
           move the process immediately to the new location before enabling
           the controllers.  */
        ret = crun_ensure_directory (dir, 0755, true, err);
        if (UNLIKELY (ret < 0))
          return ret;

        ret = move_process_to_cgroup (pid, NULL, path, err);
        if (UNLIKELY (ret < 0))
          return ret;

        ret = enable_controllers (path, err);
        if (UNLIKELY (ret < 0))
          return ret;

        if (suffix)
          {
            ret = chown_cgroups (path, args->root_uid, args->root_gid, err);
            if (UNLIKELY (ret < 0))
              return ret;
          }
      }
      break;

    default:
      return crun_make_error (err, 0, "invalid cgroup mode `%d`", cgroup_mode);
    }

  *path_out = path;
  path = NULL;

  return 0;
}

struct systemd_job_removed_s
{
  const char *path;
  const char *op;
  int terminated;
  libcrun_error_t err;
};

static int
systemd_job_removed (sd_bus_message *m, void *userdata, sd_bus_error *error arg_unused)
{
  const char *path, *unit, *result;
  uint32_t id;
  int ret;
  struct systemd_job_removed_s *d = userdata;

  ret = sd_bus_message_read (m, "uoss", &id, &path, &unit, &result);
  if (ret < 0)
    return -1;

  if (strcmp (d->path, path) == 0)
    {
      d->terminated = 1;
      if (strcmp (result, "done") != 0)
        return crun_make_error (&d->err, 0, "error `%s` systemd unit `%s`: got `%s`", d->op, unit, result);
    }
  return 0;
}

static int
systemd_check_job_status_setup (sd_bus *bus, struct systemd_job_removed_s *data, libcrun_error_t *err)
{
  int ret;

  ret = sd_bus_match_signal_async (bus, NULL, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                   "org.freedesktop.systemd1.Manager", "JobRemoved", systemd_job_removed, NULL, data);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "sd-bus match signal");

  return 0;
}

static int
systemd_check_job_status (sd_bus *bus, struct systemd_job_removed_s *data, const char *path, const char *op,
                          libcrun_error_t *err)
{
  int sd_err;

  data->path = path;
  data->op = op;
  while (! data->terminated)
    {
      sd_err = sd_bus_process (bus, NULL);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus process");

      if (sd_err != 0)
        continue;

      sd_err = sd_bus_wait (bus, (uint64_t) -1);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus wait");
    }

  if (data->err != NULL)
    {
      *err = data->err;
      return -1;
    }

  return 0;
}

int
parse_sd_array (char *s, char **out, char **next, libcrun_error_t *err)
{
  char endchr;
  char *it, *dest;
  bool escaped = false;

  *out = NULL;
  *next = NULL;

  while (isspace (*s))
    s++;
  if (*s == '\0')
    return 0;
  else if (*s != '\'' && *s != '"')
    return crun_make_error (err, 0, "invalid string `%s`", s);

  it = s;
  endchr = *it++;
  *out = dest = it;

  while (1)
    {
      if (*it == '\0')
        return crun_make_error (err, 0, "invalid string `%s`", s);
      if (*it == endchr && ! escaped)
        {
          *it++ = '\0';
          while (isspace (*it))
            it++;
          if (*it == ',')
            {
              *next = ++it;
              *dest = '\0';
              return 0;
            }

          if (*it == ']' || *it == '\0')
            {
              *dest = '\0';
              return 0;
            }

          return crun_make_error (err, 0, "invalid character found `%c`", *it);
        }

      escaped = *it == '\\' ? ! escaped : false;
      if (! escaped)
        *dest++ = *it;
      it++;
    }

  return 0;
}

/* Parse a gvariant string.  Support only a subset of types, just enough for systemd .  */
static int
append_systemd_annotation (sd_bus_message *m, const char *name, size_t name_len, const char *value,
                           libcrun_error_t *err)
{
  cleanup_free char *tmp_name = NULL;
  uint32_t factor = 1;
  const char *it;
  int sd_err;

  while (*value == ' ')
    value++;

  it = value;

  /* If the name has the form NameSec, convert it to NameUSec.  */
  if (name_len > 4 && name[name_len - 4] != 'U' && name[name_len - 3] == 'S' && name[name_len - 2] == 'e'
      && name[name_len - 1] == 'c')
    {
      factor = 1000000;

      tmp_name = xmalloc (name_len + 2);
      memcpy (tmp_name, name, name_len - 3);
      memcpy (tmp_name + name_len - 3, "USec", 5);

      name = tmp_name;
    }

  if ((strcmp (it, "true") == 0) || (strcmp (it, "false") == 0))
    {
      bool b = *it == 't';

      sd_err = sd_bus_message_append (m, "(sv)", name, "b", b);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (*it == '\'')
    {
      cleanup_free char *v_start = NULL;
      char *end;

      it = v_start = xstrdup (value);

      end = strchr (it + 1, '\'');
      if (end == NULL)
        return crun_make_error (err, 0, "invalid variant `%s`", value);
      *end = '\0';

      sd_err = sd_bus_message_append (m, "(sv)", name, "s", it + 1);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (*it == '[')
    {
      cleanup_free char *v_start = NULL;
      size_t n_parts = 0, parts_size = 32;
      cleanup_free char **parts = xmalloc (sizeof (char *) * parts_size);
      char *part;

      part = v_start = xstrdup (it + 1);
      while (1)
        {
          char *out = NULL, *next = NULL;
          int ret;

          ret = parse_sd_array (part, &out, &next, err);
          if (UNLIKELY (ret < 0))
            return ret;

          parts[n_parts++] = out;
          if (n_parts == parts_size - 1)
            {
              parts_size += 32;
              parts = xrealloc (parts, parts_size);
            }
          parts[n_parts] = NULL;
          if (next == NULL)
            break;

          part = next;
        }

      sd_err = sd_bus_message_open_container (m, 'r', "sv");
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus open container");

      sd_err = sd_bus_message_append (m, "s", name);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      sd_err = sd_bus_message_open_container (m, 'v', "as");
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus open container");

      sd_err = sd_bus_message_append_strv (m, parts);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      sd_err = sd_bus_message_close_container (m);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus close container");

      sd_err = sd_bus_message_close_container (m);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus close container");

      return 0;
    }
  else if (has_prefix (it, "uint64 "))
    {
      char *endptr = NULL;
      uint64_t v;

      errno = 0;
      v = strtoull (it + sizeof ("uint64"), &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "t", (uint64_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (has_prefix (it, "int64 "))
    {
      char *endptr = NULL;
      int64_t v;

      errno = 0;
      v = strtoll (it + sizeof ("int64"), &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "x", (int64_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (has_prefix (it, "uint32 "))
    {
      char *endptr = NULL;
      uint32_t v;

      errno = 0;
      v = strtoul (it + sizeof ("uint32"), &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "u", (uint32_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (has_prefix (it, "int32 ") || strchr (it, ' ') == NULL)
    {
      char *endptr = NULL;
      int32_t v;

      /* If no type is specified, try to parse it as int32.  */

      errno = 0;
      if (has_prefix (it, "int32 "))
        v = strtol (it + sizeof ("int32"), &endptr, 10);
      else
        v = strtol (it, &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "i", (int32_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }

  return crun_make_error (err, errno, "unknown type for `%s`", name);
}

static int
open_sd_bus_connection (sd_bus **bus, libcrun_error_t *err)
{
  int sd_err;

  sd_err = sd_bus_default_user (bus);
  if (sd_err < 0)
    {
      sd_err = sd_bus_default_system (bus);
      if (sd_err < 0)
        return crun_make_error (err, -sd_err, "cannot open sd-bus");
    }
  return 0;
}

static int
get_value_from_unified_map (runtime_spec_schema_config_linux_resources *resources, const char *name,
                            uint64_t *value, libcrun_error_t *err)
{
  size_t i;

  if (resources == NULL || resources->unified == NULL)
    return 0;

  for (i = 0; i < resources->unified->len; i++)
    if (strcmp (resources->unified->keys[i], name) == 0)
      {
        errno = 0;
        *value = (uint64_t) strtoll (resources->unified->values[i], NULL, 10);
        if (UNLIKELY (errno))
          return crun_make_error (err, errno, "invalid value for `%s`: %s", name,
                                  resources->unified->values[i]);
        return 1;
      }
  return 0;
}

static inline int
get_memory_limit (runtime_spec_schema_config_linux_resources *resources, uint64_t *limit, libcrun_error_t *err)
{
  if (resources->memory && resources->memory->limit_present)
    {
      *limit = resources->memory->limit;
      return 1;
    }

  return get_value_from_unified_map (resources, "memory.max", limit, err);
}

static inline int
get_weight (runtime_spec_schema_config_linux_resources *resources, uint64_t *weight, libcrun_error_t *err)
{
  if (resources->cpu && resources->cpu->shares_present)
    {
      /* Docker uses shares == 0 to specify no limit.  */
      if (resources->cpu->shares == 0)
        return 0;
      *weight = convert_shares_to_weight (resources->cpu->shares);
      return 1;
    }

  return get_value_from_unified_map (resources, "cpu.weight", weight, err);
}

static int
append_resources (sd_bus_message *m,
                  runtime_spec_schema_config_linux_resources *resources,
                  int cgroup_mode,
                  libcrun_error_t *err)
{
  uint64_t memory_limit;
  int sd_err;
  int ret;

  if (resources == NULL)
    return 0;

  ret = get_memory_limit (resources, &memory_limit, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret)
    {
      sd_err = sd_bus_message_append (m, "(sv)", "MemoryLimit", "t", memory_limit);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append MemoryLimit");
    }

  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      {
        uint64_t weight;

        ret = get_weight (resources, &weight, err);
        if (UNLIKELY (ret < 0))
          return ret;

        if (ret)
          {
            sd_err = sd_bus_message_append (m, "(sv)", "CPUWeight", "t", weight);
            if (UNLIKELY (sd_err < 0))
              return crun_make_error (err, -sd_err, "sd-bus message append CPUWeight");
          }
      }
      break;

    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      if (resources->cpu && resources->cpu->shares > 0)
        {
          sd_err = sd_bus_message_append (m, "(sv)", "CPUShares", "t", resources->cpu->shares);
          if (UNLIKELY (sd_err < 0))
            return crun_make_error (err, -sd_err, "sd-bus message append CPUShares");
        }
      break;

    default:
      return crun_make_error (err, 0, "invalid cgroup mode `%d`", cgroup_mode);
    }

  return 0;
}

static int
reset_failed_unit (sd_bus *bus, const char *unit)
{
  int sd_err;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus_message *m = NULL, *reply = NULL;

  sd_err = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager", "ResetFailedUnit");
  if (UNLIKELY (sd_err < 0))
    goto exit;

  sd_err = sd_bus_message_append (m, "s", unit);
  if (UNLIKELY (sd_err < 0))
    goto exit;

  sd_err = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (sd_err < 0))
    goto exit;

  sd_err = 0;

exit:
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);

  return sd_err;
}

static int
enter_systemd_cgroup_scope (runtime_spec_schema_config_linux_resources *resources,
                            int cgroup_mode,
                            json_map_string_string *annotations,
                            const char *scope, const char *slice,
                            pid_t pid, libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int sd_err, ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object = NULL;
  struct systemd_job_removed_s job_data = {};
  int i;
  const char *boolean_opts[10];

  i = 0;
  boolean_opts[i++] = "Delegate";
  if (resources)
    {
      if (resources->cpu)
        boolean_opts[i++] = "CPUAccounting";
      if (resources->memory)
        boolean_opts[i++] = "MemoryAccounting";
      if (resources->block_io)
        boolean_opts[i++] = "IOAccounting";
      if (resources->pids)
        boolean_opts[i++] = "TasksAccounting";
    }
  boolean_opts[i++] = NULL;

  ret = open_sd_bus_connection (&bus, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = systemd_check_job_status_setup (bus, &job_data, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  sd_err = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager", "StartTransientUnit");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "set up dbus message");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "ss", scope, "fail");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append scope");
      goto exit;
    }

  sd_err = sd_bus_message_open_container (m, 'a', "(sv)");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus open container");
      goto exit;
    }

  if (slice)
    {
      sd_err = sd_bus_message_append (m, "(sv)", "Slice", "s", slice);
      if (UNLIKELY (sd_err < 0))
        {
          ret = crun_make_error (err, -sd_err, "sd-bus message append Slice");
          goto exit;
        }
    }

  if (annotations)
    {
      size_t prefix_len = sizeof (SYSTEMD_PROPERTY_PREFIX) - 1;
      size_t i;

      for (i = 0; i < annotations->len; i++)
        {
          size_t len;

          if (! has_prefix (annotations->keys[i], SYSTEMD_PROPERTY_PREFIX))
            continue;

          len = strlen (annotations->keys[i]);
          if (len < prefix_len + 3)
            {
              ret = crun_make_error (err, EINVAL, "invalid systemd property name `%s`", annotations->keys[i]);
              goto exit;
            }

          ret = append_systemd_annotation (m, annotations->keys[i] + prefix_len, len - prefix_len,
                                           annotations->values[i], err);
          if (UNLIKELY (ret < 0))
            goto exit;
        }
    }

  sd_err = sd_bus_message_append (m, "(sv)", "Description", "s", "libcrun container");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append Description");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "(sv)", "PIDs", "au", 1, pid);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append PIDs");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "(sv)", "DefaultDependencies", "b", 0);

  for (i = 0; boolean_opts[i]; i++)
    {
      sd_err = sd_bus_message_append (m, "(sv)", boolean_opts[i], "b", 1);
      if (UNLIKELY (sd_err < 0))
        {
          ret = crun_make_error (err, -sd_err, "sd-bus message append `%s`", boolean_opts[i]);
          goto exit;
        }
    }

  ret = append_resources (m, resources, cgroup_mode, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  sd_err = sd_bus_message_close_container (m);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus close container");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "a(sa(sv))", 0);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  sd_err = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (sd_err < 0))
    {
      if (reset_failed_unit (bus, scope) == 0)
        {
          sd_bus_error_free (&error);
          if (reply)
            sd_bus_message_unref (reply);

          error = SD_BUS_ERROR_NULL;
          reply = NULL;

          sd_err = sd_bus_call (bus, m, 0, &error, &reply);
        }
      if (sd_err < 0)
        {
          ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call: %s", error.message ?: error.name);
          goto exit;
        }
    }

  sd_err = sd_bus_message_read (reply, "o", &object);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message read");
      goto exit;
    }

  ret = systemd_check_job_status (bus, &job_data, object, "creating", err);

exit:
  if (bus)
    sd_bus_unref (bus);
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);
  return ret;
}

static int
libcrun_destroy_systemd_cgroup_scope (struct libcrun_cgroup_status *cgroup_status,
                                      libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object;
  const char *scope = cgroup_status->scope;
  struct systemd_job_removed_s job_data = {};

  ret = open_sd_bus_connection (&bus, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = systemd_check_job_status_setup (bus, &job_data, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                        "org.freedesktop.systemd1.Manager", "StopUnit");
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "set up dbus message");
      goto exit;
    }

  ret = sd_bus_message_append (m, "ss", scope, "replace");
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "sd-bus message append");
      goto exit;
    }

  ret = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call: %s", error.message ?: error.name);
      goto exit;
    }

  ret = sd_bus_message_read (reply, "o", &object);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "sd-bus message read");
      goto exit;
    }

  ret = systemd_check_job_status (bus, &job_data, object, "removing", err);

exit:
  if (bus)
    sd_bus_unref (bus);
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);
  return ret;
}

static const char *
find_systemd_subgroup (json_map_string_string *annotations)
{
  const char *annotation;

  annotation = find_annotation_map (annotations, "run.oci.systemd.subgroup");
  if (annotation)
    {
      if (annotation[0] == '\0')
        return NULL;
      return annotation;
    }

  return "container";
}

static int
libcrun_cgroup_enter_systemd (struct libcrun_cgroup_args *args,
                              struct libcrun_cgroup_status *out,
                              libcrun_error_t *err)
{
  runtime_spec_schema_config_linux_resources *resources = args->resources;
  const char *cgroup_path = args->cgroup_path;
  cleanup_free char *scope = NULL;
  cleanup_free char *path = NULL;
  cleanup_free char *slice = NULL;
  const char *suffix;
  const char *id = args->id;
  pid_t pid = args->pid;
  int cgroup_mode;
  int ret;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  get_systemd_scope_and_slice (id, cgroup_path, &scope, &slice);

  ret = enter_systemd_cgroup_scope (resources, cgroup_mode, args->annotations, scope, slice, pid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  suffix = find_systemd_subgroup (args->annotations);

  ret = systemd_finalize (args, &path, cgroup_mode, suffix, err);
  if (UNLIKELY (ret < 0))
    return ret;

  out->path = path;
  path = NULL;

  out->scope = scope;
  scope = NULL;
  return 0;
}

char *
get_cgroup_scope_path (const char *cgroup_path, const char *scope)
{
  char *path_to_scope = NULL;
  char *cur;

  path_to_scope = xstrdup (cgroup_path);

  cur = strchr (path_to_scope, '/');
  while (cur)
    {
      char *next = strchr (cur + 1, '/');
      if (next == NULL)
        break;

      *next = '\0';
      if (strcmp (cur, scope) == 0)
        return path_to_scope;
      *next = '/';

      cur = next;
      while (*cur == '/')
        cur++;
    }

  return path_to_scope;
}

static int
libcrun_destroy_cgroup_systemd (struct libcrun_cgroup_status *cgroup_status,
                                libcrun_error_t *err)
{
  cleanup_free char *path_to_scope = NULL;
  int mode;
  int ret;

  mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (mode < 0))
    return mode;

  ret = cgroup_killall_path (cgroup_status->path, SIGKILL, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  ret = libcrun_destroy_systemd_cgroup_scope (cgroup_status, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  path_to_scope = get_cgroup_scope_path (cgroup_status->path, cgroup_status->scope);

  return destroy_cgroup_path (path_to_scope, mode, err);
}

static int
libcrun_update_resources_systemd (struct libcrun_cgroup_status *cgroup_status,
                                  runtime_spec_schema_config_linux_resources *resources,
                                  libcrun_error_t *err)
{
  struct systemd_job_removed_s job_data = {};
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus_message *reply = NULL;
  sd_bus_message *m = NULL;
  sd_bus *bus = NULL;
  int sd_err, ret;
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  ret = open_sd_bus_connection (&bus, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = systemd_check_job_status_setup (bus, &job_data, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  sd_err = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "SetUnitProperties");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "set up dbus message");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "sb", cgroup_status->scope, 1);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  sd_err = sd_bus_message_open_container (m, 'a', "(sv)");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus open container");
      goto exit;
    }

  ret = append_resources (m, resources, cgroup_mode, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  sd_err = sd_bus_message_close_container (m);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus close container");
      goto exit;
    }

  sd_err = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call: %s", error.message ?: error.name);
      goto exit;
    }

  if (cgroup_mode != CGROUP_MODE_UNIFIED)
    {
      ret = setup_rt_runtime (resources, cgroup_status->path, err);
      if (UNLIKELY (ret < 0))
        goto exit;
    }

  ret = 0;

exit:
  if (bus)
    sd_bus_unref (bus);
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);
  return ret;
}

#else
static int
libcrun_cgroup_enter_systemd (struct libcrun_cgroup_args *args,
                              struct libcrun_cgroup_status *out,
                              libcrun_error_t *err)
{
  (void) args;
  (void) out;

  return crun_make_error (err, ENOTSUP, "systemd not supported");
}

static int
libcrun_destroy_cgroup_systemd (struct libcrun_cgroup_status *cgroup_status,
                                libcrun_error_t *err)
{
  (void) cgroup_status;

  return crun_make_error (err, ENOTSUP, "systemd not supported");
}

static int
libcrun_update_resources_systemd (struct libcrun_cgroup_status *cgroup_status,
                                  runtime_spec_schema_config_linux_resources *resources,
                                  libcrun_error_t *err)
{
  (void) cgroup_status;
  (void) resources;

  return crun_make_error (err, ENOTSUP, "systemd not supported");
}
#endif

struct libcrun_cgroup_manager cgroup_manager_systemd = {
  .precreate_cgroup = NULL,
  .create_cgroup = libcrun_cgroup_enter_systemd,
  .destroy_cgroup = libcrun_destroy_cgroup_systemd,
  .update_resources = libcrun_update_resources_systemd,
};
