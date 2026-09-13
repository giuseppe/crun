/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Adrian Reber <areber@redhat.com>
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

#if HAVE_CRIU && HAVE_DLOPEN

#  include <unistd.h>
#  include <sys/types.h>
#  include <criu/criu.h>
#  include <sched.h>
#  include <sys/stat.h>
#  include <sys/mount.h>
#  include <fcntl.h>

#  include "container.h"
#  include "linux.h"
#  include "status.h"
#  include "utils.h"
#  include "cgroup.h"
#  include "cgroup-utils.h"

#  ifndef STATIC
#    include <dlfcn.h>
#  endif

#  define CRIU_CHECKPOINT_LOG_FILE "dump.log"
#  define CRIU_RESTORE_LOG_FILE "restore.log"
#  define DESCRIPTORS_FILENAME "descriptors.json"
#  define CRIU_RUNC_CONFIG_FILE "/etc/criu/runc.conf"
#  define CRIU_CRUN_CONFIG_FILE "/etc/criu/crun.conf"

#  define CRIU_EXT_NETNS "extRootNetNS"
#  define CRIU_EXT_PIDNS "extRootPidNS"

#  ifndef CLONE_NEWTIME
#    define CLONE_NEWTIME 0x00000080 /* New time namespace */
#  endif

/* Defined in chroot_realpath.c  */
char *chroot_realpath (const char *chroot, const char *path, char resolved_path[]);

static const char *console_socket = NULL;

#  define LIBCRIU_MIN_VERSION 31500

struct libcriu_wrapper_s
{
  void *handle;
  int (*criu_add_ext_mount) (const char *key, const char *val);
  int (*criu_add_external) (const char *key);
  int (*criu_add_inherit_fd) (int fd, const char *key);
  int (*criu_check_version) (int minimum);
  int (*criu_dump) (void);
  int (*criu_get_orphan_pts_master_fd) (void);
  int (*criu_init_opts) (void);
#  ifdef CRIU_JOIN_NS_SUPPORT
  int (*criu_join_ns_add) (const char *ns, const char *ns_file, const char *extra_opt);
#  endif
#  ifdef CRIU_PRE_DUMP_SUPPORT
  int (*criu_feature_check) (struct criu_feature_check *features, size_t size);
  int (*criu_pre_dump) (void);
#  endif
  int (*criu_restore_child) (void);
  int (*criu_set_freeze_cgroup) (const char *name);
  void (*criu_set_file_locks) (bool file_locks);
  void (*criu_set_ext_unix_sk) (bool ext_unix_sk);
  int (*criu_set_log_file) (const char *log_file);
  void (*criu_set_log_level) (int log_level);
  void (*criu_set_leave_running) (bool leave_running);
  void (*criu_set_manage_cgroups) (bool manage);
  void (*criu_set_manage_cgroups_mode) (enum criu_cg_mode mode);
  int (*criu_set_network_lock) (enum criu_network_lock_method method);
  void (*criu_set_notify_cb) (int (*cb) (char *action, criu_notify_arg_t na));
  void (*criu_set_orphan_pts_master) (bool orphan_pts_master);
  void (*criu_set_images_dir_fd) (int fd);
  int (*criu_set_parent_images) (const char *path);
  void (*criu_set_pid) (int pid);
  int (*criu_set_root) (const char *root);
  int (*criu_add_cg_root) (const char *ctrl, const char *path);
  void (*criu_set_shell_job) (bool shell_job);
  void (*criu_set_tcp_established) (bool tcp_established);
  void (*criu_set_tcp_close) (bool tcp_close);
  void (*criu_set_track_mem) (bool track_mem);
  void (*criu_set_work_dir_fd) (int fd);
  int (*criu_set_lsm_profile) (const char *name);
  int (*criu_set_lsm_mount_context) (const char *name);
  int (*criu_set_config_file) (const char *path);
};

static struct libcriu_wrapper_s *libcriu_wrapper;

static inline void
cleanup_wrapper (void *p)
{
  struct libcriu_wrapper_s **w;

  w = (struct libcriu_wrapper_s **) p;
  if (*w == NULL)
    return;

#  ifndef STATIC
  if ((*w)->handle)
    dlclose ((*w)->handle);
#  endif
  free (*w);
  libcriu_wrapper = NULL;
}

#  define cleanup_wrapper __attribute__ ((cleanup (cleanup_wrapper)))

static int
load_wrapper (struct libcriu_wrapper_s **wrapper_out, libcrun_error_t *err)
{
  cleanup_free struct libcriu_wrapper_s *wrapper = xmalloc0 (sizeof (*wrapper));

#  ifdef STATIC
#    define LOAD_CRIU_FUNCTION(X, ALLOW_NULL) \
      wrapper->X = &X;
#  else
#    define LOAD_CRIU_FUNCTION(X, ALLOW_NULL)                                                    \
      do                                                                                         \
        {                                                                                        \
          wrapper->X = dlsym (wrapper->handle, #X);                                              \
          if (! ALLOW_NULL && wrapper->X == NULL)                                                \
            {                                                                                    \
              dlclose (wrapper->handle);                                                         \
              return crun_make_error (err, 0, "could not find symbol `%s` in `libcriu.so`", #X); \
            }                                                                                    \
      } while (0)
#  endif

#  ifndef STATIC
  wrapper->handle = dlopen ("libcriu.so.2", RTLD_NOW);
  if (wrapper->handle == NULL)
    return crun_make_error (err, 0, "could not load `libcriu.so.2`: `%s`", dlerror ());
#  endif

  LOAD_CRIU_FUNCTION (criu_add_ext_mount, false);
  LOAD_CRIU_FUNCTION (criu_add_external, false);
  LOAD_CRIU_FUNCTION (criu_add_inherit_fd, false);
  LOAD_CRIU_FUNCTION (criu_check_version, false);
  LOAD_CRIU_FUNCTION (criu_dump, false);
  LOAD_CRIU_FUNCTION (criu_get_orphan_pts_master_fd, false);
  LOAD_CRIU_FUNCTION (criu_init_opts, false);

#  ifdef CRIU_JOIN_NS_SUPPORT
  /* criu_join_ns_add() API was introduced with CRIU version 3.16.1
   * Here we check if this API is available at build time to support
   * compiling with older version of CRIU, and at runtime to support
   * running crun with older versions of libcriu.so.2.
   */
  LOAD_CRIU_FUNCTION (criu_join_ns_add, true);
#  endif

#  ifdef CRIU_PRE_DUMP_SUPPORT
  LOAD_CRIU_FUNCTION (criu_feature_check, false);
  LOAD_CRIU_FUNCTION (criu_pre_dump, false);
#  endif
  LOAD_CRIU_FUNCTION (criu_restore_child, false);
  LOAD_CRIU_FUNCTION (criu_set_ext_unix_sk, false);
  LOAD_CRIU_FUNCTION (criu_set_file_locks, false);
  LOAD_CRIU_FUNCTION (criu_set_freeze_cgroup, false);
  LOAD_CRIU_FUNCTION (criu_set_images_dir_fd, false);
  LOAD_CRIU_FUNCTION (criu_set_leave_running, false);
  LOAD_CRIU_FUNCTION (criu_set_log_file, false);
  LOAD_CRIU_FUNCTION (criu_set_log_level, false);
  LOAD_CRIU_FUNCTION (criu_set_manage_cgroups, false);
  LOAD_CRIU_FUNCTION (criu_set_manage_cgroups_mode, false);
  LOAD_CRIU_FUNCTION (criu_set_network_lock, true);
  LOAD_CRIU_FUNCTION (criu_set_notify_cb, false);
  LOAD_CRIU_FUNCTION (criu_set_orphan_pts_master, false);
  LOAD_CRIU_FUNCTION (criu_set_parent_images, false);
  LOAD_CRIU_FUNCTION (criu_set_pid, false);
  LOAD_CRIU_FUNCTION (criu_set_root, false);
  LOAD_CRIU_FUNCTION (criu_add_cg_root, false);
  LOAD_CRIU_FUNCTION (criu_set_shell_job, false);
  LOAD_CRIU_FUNCTION (criu_set_tcp_established, false);
  LOAD_CRIU_FUNCTION (criu_set_tcp_close, false);
  LOAD_CRIU_FUNCTION (criu_set_track_mem, false);
  LOAD_CRIU_FUNCTION (criu_set_work_dir_fd, false);
  LOAD_CRIU_FUNCTION (criu_set_lsm_profile, false);
  LOAD_CRIU_FUNCTION (criu_set_lsm_mount_context, false);
#  if ! defined STATIC || defined CRIU_CONFIG_FILE
  LOAD_CRIU_FUNCTION (criu_set_config_file, true);
#  endif

  libcriu_wrapper = *wrapper_out = wrapper;
  wrapper = NULL;
#  undef LOAD_CRIU_FUNCTION
  return 0;
}

static int
criu_notify (char *action, __attribute__ ((unused)) criu_notify_arg_t na)
{
  if (strncmp (action, "orphan-pts-master", 17) == 0)
    {
      /* CRIU sends us the master FD via the 'orphan-pts-master'
       * callback and we are passing it on to the '--console-socket'
       * if it exists. */
      cleanup_close int console_socket_fd = -1;
      libcrun_error_t tmp_err = NULL;
      int master_fd;
      int ret;

      if (! console_socket)
        return 0;

      master_fd = libcriu_wrapper->criu_get_orphan_pts_master_fd ();

      console_socket_fd = open_unix_domain_client_socket (console_socket, 0, &tmp_err);
      if (UNLIKELY (console_socket_fd < 0))
        {
          libcrun_error_release (&tmp_err);
          return console_socket_fd;
        }
      ret = send_fd_to_socket (console_socket_fd, master_fd, &tmp_err);
      if (UNLIKELY (ret < 0))
        {
          libcrun_error_release (&tmp_err);
          return ret;
        }
    }
  return 0;
}

#  ifdef CRIU_PRE_DUMP_SUPPORT

static int
criu_check_mem_track (libcrun_error_t *err)
{
  struct criu_feature_check features = { 0 };
  int ret;

  /* Right now we are only interested in checking memory tracking.
   * Memory tracking can be disabled at different levels. aarch64
   * for example has memory tracking not implemented. It could also
   * be not enabled on other architectures. Just ask CRIU if that
   * features exists. */

  features.mem_track = true;

  ret = libcriu_wrapper->criu_feature_check (&features, sizeof (features));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU feature checking failed: %d", ret);

  if (features.mem_track == true)
    return 1;

  return crun_make_error (err, 0, "CRIU memory tracking not supported");
}

#  endif

static int
register_masked_paths_mounts (runtime_spec_schema_config_schema *def, libcrun_container_t *container,
                              struct libcriu_wrapper_s *libcriu_wrapper, bool is_restore, libcrun_error_t *err)
{
  cleanup_free char *empty_dir_path = NULL;
  bool shared_dir_registered = false;
  size_t i;
  int ret;

  for (i = 0; i < def->linux->masked_paths_len; i++)
    {
      struct stat statbuf;
      ret = stat (def->linux->masked_paths[i], &statbuf);
      if (ret != 0)
        continue;

      if (S_ISDIR (statbuf.st_mode))
        {
          if (! shared_dir_registered)
            {
              ret = get_shared_empty_directory_path (&empty_dir_path,
                                                     (container->context ? container->context->state_root : NULL), err);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = libcriu_wrapper->criu_add_ext_mount (empty_dir_path, empty_dir_path);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, -ret, "CRIU: failed adding external mount for shared empty directory `%s`", empty_dir_path);

              shared_dir_registered = true;
            }

          ret = libcriu_wrapper->criu_add_ext_mount (def->linux->masked_paths[i], empty_dir_path);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount for masked directory `%s`", def->linux->masked_paths[i]);
        }
      else if (S_ISREG (statbuf.st_mode))
        {
          const char *bind_target = is_restore ? "/dev/null" : def->linux->masked_paths[i];
          ret = libcriu_wrapper->criu_add_ext_mount (def->linux->masked_paths[i], bind_target);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", bind_target);
        }
    }

  return 0;
}

/* Parse one /proc/self/cgroup LINE into its subsystem, normalizing the name and
   stripping any "name=" prefix.  When SUBPATH_OUT is not NULL, the in-hierarchy
   path is stored there.  Returns the subsystem, or NULL if the line carries no
   controller and should be skipped.  LINE is modified in place.  */
static char *
parse_cgroup_subsystem (char *line, char **subpath_out)
{
  char *subsystem, *subpath, *it;

  subsystem = strchr (line, ':') + 1;
  subpath = strchr (subsystem, ':') + 1;
  *(subpath - 1) = '\0';

  if (subsystem[0] == '\0')
    return NULL;

  it = strstr (subsystem, "name=");
  if (it)
    subsystem = it + 5;

  if (strcmp (subsystem, "net_prio,net_cls") == 0)
    subsystem = "net_cls,net_prio";
  if (strcmp (subsystem, "cpuacct,cpu") == 0)
    subsystem = "cpu,cpuacct";

  if (subpath_out)
    *subpath_out = subpath;
  return subsystem;
}

static int
restore_cgroup_v1_mount (runtime_spec_schema_config_schema *def, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  bool has_cgroup_mount = false;
  char *saveptr = NULL;
  int cgroup_mode;
  char *from;
  int ret;
  uint32_t i;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    return 0;

  /* First check if there is actually a cgroup mount in the container. */
  for (i = 0; i < def->mounts_len; i++)
    {
      char *type = def->mounts[i]->type;
      if (type && strcmp (type, "cgroup") == 0)
        {
          has_cgroup_mount = true;
          break;
        }
    }

  if (! has_cgroup_mount)
    return 0;

  ret = read_all_file (PROC_SELF_CGROUP, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, 0, "invalid content from `%s`", PROC_SELF_CGROUP);

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *destination = NULL;
      cleanup_free char *source = NULL;
      char *subsystem;
      char *subpath;

      subsystem = parse_cgroup_subsystem (from, &subpath);
      if (subsystem == NULL)
        continue;

      ret = append_paths (&source, err, CGROUP_ROOT, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&destination, err, source, subpath, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcriu_wrapper->criu_add_ext_mount (source, destination);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", destination);
    }

  return 0;
}

static int
checkpoint_cgroup_v1_mount (runtime_spec_schema_config_schema *def, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  bool has_cgroup_mount = false;
  char *saveptr = NULL;
  char *from;
  int ret;
  uint32_t i;

  /* First check if there is actually a cgroup mount in the container. */
  for (i = 0; i < def->mounts_len; i++)
    {
      char *type = def->mounts[i]->type;
      if (type && strcmp (type, "cgroup") == 0)
        {
          has_cgroup_mount = true;
          break;
        }
    }

  if (! has_cgroup_mount)
    return 0;

  ret = read_all_file (PROC_SELF_CGROUP, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, 0, "invalid content from `%s`", PROC_SELF_CGROUP);

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *source_path = NULL;
      char *subsystem;

      subsystem = parse_cgroup_subsystem (from, NULL);
      if (subsystem == NULL)
        continue;

      ret = append_paths (&source_path, err, CGROUP_ROOT, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcriu_wrapper->criu_add_ext_mount (source_path, source_path);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", source_path);
    }

  return 0;
}

static int
handle_criu_config_file (libcrun_container_t *container, libcrun_error_t *err)
{
  int ret;
  const char *criu_config_annotation;
  const char *config_file = CRIU_RUNC_CONFIG_FILE;

  criu_config_annotation = find_annotation (container, "org.criu.config");

  /* Ignore missing criu_set_config_file() API for compatibility with older CRIU versions,
   * and show an error only if config file is explicitly set with annotation.
   */
  if (libcriu_wrapper->criu_set_config_file == NULL)
    {
      if (criu_config_annotation)
        return crun_make_error (err, 0, "libcriu RPC config files supported in CRIU >= 4.2");

      return 0;
    }

  if (criu_config_annotation)
    config_file = criu_config_annotation;
  else if (access (CRIU_CRUN_CONFIG_FILE, F_OK) == 0)
    config_file = CRIU_CRUN_CONFIG_FILE;

  ret = libcriu_wrapper->criu_set_config_file (config_file);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "failed to set CRIU config file");

  return 0;
}

static int
validate_criu_version (libcrun_error_t *err)
{
  int ret;

  // validate that the libcriu version is at least LIBCRIU_MIN_VERSION
  ret = libcriu_wrapper->criu_check_version (LIBCRIU_MIN_VERSION);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "CRIU: failed checking version");

  if (ret == 0)
    return crun_make_error (err, 0, "libcriu is too old");

  return 0;
}

static void
show_criu_log (const char *work_path, const char *log)
{
  cleanup_free char *log_path = NULL;
  libcrun_error_t *tmp_err = NULL;
  char line[1024];
  FILE *f;

  if (UNLIKELY (append_paths (&log_path, tmp_err, work_path, log, NULL)) < 0)
    {
      crun_error_release (tmp_err);
      return;
    }

  f = fopen (log_path, "r");
  if (f == NULL)
    {
      if (errno != ENOENT)
        libcrun_error (errno, "Can't open CRIU log `%s`", log_path);
      return;
    }

  /* Log with error verbosity as this is the default. */
  libcrun_error (0, "--- excerpt from CRIU log `%s`", log_path);
  while (fgets (line, sizeof (line), f) != NULL)
    if (strstr (line, "Error ") != NULL)
      {
        line[strcspn (line, "\n")] = '\0';
        libcrun_error (0, "%s", line);
      }

  fclose (f);
  libcrun_error (0, "--- end of excerpt");
}

/* work_dir is the place CRIU will put its logfiles.  If not explicitly set, CRIU
 * will put the logfiles into the images_dir.  When set, create and open it and
 * hand the fd to CRIU; ownership of the returned fd stays with the caller.  */
static int
setup_criu_work_dir (libcrun_checkpoint_restore_t *cr_options, int *work_fd_out, libcrun_error_t *err)
{
  int work_fd;

  if (cr_options->work_path == NULL)
    {
      /* This is only for the error message later. */
      cr_options->work_path = cr_options->image_path;
      return 0;
    }

  if (UNLIKELY ((mkdir (cr_options->work_path, 0700) == -1) && (errno != EEXIST)))
    return crun_make_error (err, errno, "error creating CRIU work directory `%s`", cr_options->work_path);

  work_fd = open (cr_options->work_path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (work_fd == -1))
    return crun_make_error (err, errno, "error opening CRIU work directory `%s`", cr_options->work_path);

  libcriu_wrapper->criu_set_work_dir_fd (work_fd);
  *work_fd_out = work_fd;
  return 0;
}

int
libcrun_container_checkpoint_linux_criu (libcrun_container_status_t *status, libcrun_container_t *container,
                                         libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_wrapper struct libcriu_wrapper_s *wrapper = NULL;
  cleanup_free char *descriptors_path = NULL;
  cleanup_free char *freezer_path = NULL;
  cleanup_free char *path = NULL;
  cleanup_close int image_fd = -1;
  cleanup_close int work_fd = -1;
  int cgroup_mode;
  size_t i;
  int ret;

  ret = load_wrapper (&wrapper, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (geteuid ())
    return crun_make_error (err, 0, "checkpointing requires root");

  /* No CRIU version or feature checking yet. In configure.ac there
   * is a minimum CRIU version listed and so far it is good enough.
   *
   * The CRIU library also does not yet have an interface to CRIU
   * the version of the binary. Right now it is only possible to
   * query the version of the library via defines during buildtime.
   *
   * The whole CRIU library setup works this way, that the library
   * is only a wrapper around RPC calls to the actual library. So
   * if CRIU is updated and the SO of the library does not change,
   * and crun is not rebuilt against the newer version, the version
   * is still returning the values during buildtime and not from
   * the actual running CRIU binary. The RPC interface between the
   * library will not break, so no reason to worry, but it is not
   * possible to detect (via the library) which CRIU version is
   * actually being used. This needs to be added to CRIU upstream. */

  ret = libcriu_wrapper->criu_init_opts ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU init failed with %d", ret);

  ret = validate_criu_version (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (cr_options->image_path == NULL))
    return crun_make_error (err, 0, "image path not set");

  ret = mkdir (cr_options->image_path, 0700);
  if (UNLIKELY ((ret == -1) && (errno != EEXIST)))
    return crun_make_error (err, errno, "error creating checkpoint directory `%s`", cr_options->image_path);

  image_fd = open (cr_options->image_path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (image_fd == -1))
    return crun_make_error (err, errno, "error opening checkpoint directory `%s`", cr_options->image_path);

  libcriu_wrapper->criu_set_images_dir_fd (image_fd);

  /* Set up logging. */
  libcriu_wrapper->criu_set_log_level (4);
  libcriu_wrapper->criu_set_log_file (CRIU_CHECKPOINT_LOG_FILE);

  /* Set up CRIU config file */
  if (UNLIKELY (handle_criu_config_file (container, err)))
    return -1;

  /* Setting the pid early as we can skip a lot of checkpoint setup if
   * we just do a pre-dump. The PID needs to be set always. Do it here.
   * The main process of the container is the process CRIU will checkpoint
   * and all of its children. */
  libcriu_wrapper->criu_set_pid (status->pid);

  ret = setup_criu_work_dir (cr_options, &work_fd, err);
  if (UNLIKELY (ret < 0))
    return ret;

#  ifdef CRIU_PRE_DUMP_SUPPORT

  {
    int criu_can_mem_track = 0;
    /* If the user uses --pre-dump for the second time or does
     * a final dump from a previous pre-dump, setting parent_path
     * is necessary so that CRIU can find which pages have not
     * changed compared to the previous dump. */
    if (cr_options->parent_path != NULL)
      {
        criu_can_mem_track = criu_check_mem_track (err);
        if (UNLIKELY (criu_can_mem_track == -1))
          return -1;
        libcriu_wrapper->criu_set_track_mem (true);

        /* The parent path must be relative to image path (something like ../previous-dump).
           CRIU will fail with an unclear error message if the path is not right.
         */
        if (UNLIKELY (cr_options->parent_path[0] == '/'))
          return crun_make_error (err, 0, "--parent-path must be relative");
        int is_dir = crun_dir_p_at (image_fd, cr_options->parent_path, false, err);
        if (UNLIKELY (is_dir <= 0))
          {
            if (is_dir < 0)
              return crun_error_wrap (err, "invalid --parent-path");
            return crun_make_error (err, ENOTDIR, "invalid --parent-path");
          }
        ret = libcriu_wrapper->criu_set_parent_images (cr_options->parent_path);
        if (UNLIKELY (ret != 0))
          return crun_make_error (err, -ret, "error setting CRIU parent images path to `%s`", cr_options->parent_path);
      }

    if (cr_options->pre_dump)
      {
        if (criu_can_mem_track != 1)
          {
            criu_can_mem_track = criu_check_mem_track (err);
            if (UNLIKELY (criu_can_mem_track == -1))
              return -1;
          }
        libcriu_wrapper->criu_set_track_mem (true);
        ret = libcriu_wrapper->criu_pre_dump ();
        if (UNLIKELY (ret != 0))
          {
            show_criu_log (cr_options->work_path, CRIU_CHECKPOINT_LOG_FILE);
            return crun_make_error (err, 0, "CRIU pre-dump failed: %d", ret);
          }
        return 0;
      }
  }
#  endif

  /* descriptors.json is needed during restore to correctly
   * reconnect stdin, stdout, stderr. */
  ret = append_paths (&descriptors_path, err, cr_options->image_path, DESCRIPTORS_FILENAME, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = write_file (descriptors_path, status->external_descriptors, safe_strlen (status->external_descriptors), err);
  if (UNLIKELY (ret < 0))
    return crun_error_wrap (err, "error saving CRIU descriptors file");

  ret = append_paths (&path, err, status->bundle, status->rootfs, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcriu_wrapper->criu_set_root (path);
  if (UNLIKELY (ret != 0))
    return crun_make_error (err, 0, "error setting CRIU root to `%s`", path);

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  /* For cgroup v1 we need to tell CRIU to handle all cgroup mounts as external mounts. */
  if (cgroup_mode != CGROUP_MODE_UNIFIED)
    {
      ret = checkpoint_cgroup_v1_mount (def, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Tell CRIU about external bind mounts. */
  for (i = 0; i < def->mounts_len; i++)
    {
      bool nofollow = false;
      if (is_bind_mount (def->mounts[i], NULL, &nofollow))
        {
          /* We need to resolve mount destination inside container's root for CRIU to handle. */
          char buf[PATH_MAX];
          const char *dest_in_root;

          if (nofollow)
            return crun_make_error (err, 0, "CRIU does not support `src-nofollow` for bind mounts");

          dest_in_root = chroot_realpath (status->rootfs, def->mounts[i]->destination, buf);
          if (UNLIKELY (dest_in_root == NULL))
            return crun_make_error (err, errno, "unable to resolve external bind mount `%s` under rootfs", def->mounts[i]->destination);

          /* When the rootfs is "/" or not set, chroot_realpath returns the
             path unchanged, so strip the prefix only when it is there.  */
          if (has_prefix (dest_in_root, status->rootfs))
            dest_in_root += safe_strlen (status->rootfs);

          ret = libcriu_wrapper->criu_add_ext_mount (dest_in_root, dest_in_root);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", def->mounts[i]->destination);
        }
    }

  ret = register_masked_paths_mounts (def, container, libcriu_wrapper, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* CRIU tries to checkpoint and restore all namespaces. However,
   * namespaces could be shared between containers in a pod.
   * To address this, CRIU provides support for external namespaces.
   * External namespaces allow to ignore the namespace during checkpoint
   * and restore the container into the existing namespaces.
   *
   * We are looking at config.json and if there is a path configured for
   * a namespace we are telling CRIU to ignore the namespace and
   * just restore the container into the existing namespace.
   *
   * In the case of Podman, a network namespace would be created via CNI.
   *
   * CRIU expects the information about an external namespace like this:
   * --external <namespace>[<inode>]:<key>
   */

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);

      if (value == CLONE_NEWNET && def->linux->namespaces[i]->path != NULL)
        {
          cleanup_free char *external = NULL;
          struct stat statbuf;

          ret = stat (def->linux->namespaces[i]->path, &statbuf);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "unable to stat(): `%s`", def->linux->namespaces[i]->path);

          xasprintf (&external, "net[%ld]:" CRIU_EXT_NETNS, statbuf.st_ino);
          ret = libcriu_wrapper->criu_add_external (external);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", external);
        }

      if (value == CLONE_NEWPID && def->linux->namespaces[i]->path != NULL)
        {
          cleanup_free char *external = NULL;
          struct stat statbuf;

          ret = stat (def->linux->namespaces[i]->path, &statbuf);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "unable to stat(): `%s`", def->linux->namespaces[i]->path);

          xasprintf (&external, "pid[%ld]:" CRIU_EXT_PIDNS, statbuf.st_ino);
          ret = libcriu_wrapper->criu_add_external (external);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", external);
        }
    }

  /* Tell CRIU to use the freezer to pause all container processes. */
  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      /* This needs CRIU 3.14. */
      ret = append_paths (&freezer_path, err, CGROUP_ROOT, status->cgroup_path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = append_paths (&freezer_path, err, CGROUP_ROOT "/freezer", status->cgroup_path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcriu_wrapper->criu_set_freeze_cgroup (freezer_path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "CRIU: failed setting freezer %d", ret);

  /* Set boolean options . */
  libcriu_wrapper->criu_set_leave_running (cr_options->leave_running);
  libcriu_wrapper->criu_set_ext_unix_sk (cr_options->ext_unix_sk);
  libcriu_wrapper->criu_set_shell_job (cr_options->shell_job);
  libcriu_wrapper->criu_set_tcp_established (cr_options->tcp_established);
  libcriu_wrapper->criu_set_file_locks (cr_options->file_locks);
  libcriu_wrapper->criu_set_orphan_pts_master (true);
  if (cr_options->manage_cgroups_mode == -1)
    /* Defaulting to CRIU_CG_MODE_SOFT just as runc */
    libcriu_wrapper->criu_set_manage_cgroups_mode (CRIU_CG_MODE_SOFT);
  else
    libcriu_wrapper->criu_set_manage_cgroups_mode (cr_options->manage_cgroups_mode);

  libcriu_wrapper->criu_set_manage_cgroups (true);

  if (libcriu_wrapper->criu_set_network_lock && cr_options->network_lock_method > 0)
    {
      ret = libcriu_wrapper->criu_set_network_lock (cr_options->network_lock_method);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "CRIU: failed setting network lock");
    }

  ret = libcriu_wrapper->criu_dump ();
  if (UNLIKELY (ret != 0))
    {
      show_criu_log (cr_options->work_path, CRIU_CHECKPOINT_LOG_FILE);
      return crun_make_error (err, ret < 0 ? -ret : 0, "CRIU checkpointing failed: %d", ret);
    }

  return 0;
}

static int
prepare_restore_mounts_internal (runtime_spec_schema_config_schema *def, char *root, const char **mounted,
                                 size_t *n_mounted, libcrun_error_t *err)
{
  uint32_t i;

  /* Go through all mountpoints to be able to recreate missing mountpoints. */
  for (i = 0; i < def->mounts_len; i++)
    {
      char *dest = def->mounts[i]->destination;
      char *type = def->mounts[i]->type;
      cleanup_close int root_fd = -1;
      bool nofollow = false;
      bool on_tmpfs = false;
      int is_dir = 1;
      size_t j;

      /* cgroup restore should be handled by CRIU itself */
      if (type && (strcmp (type, "cgroup") == 0 || strcmp (type, "cgroup2") == 0))
        continue;

      /* Check if the mountpoint is on a tmpfs. CRIU restores
       * all tmpfs. We do need to recreate directories on a tmpfs. */
      size_t dest_len = strlen (dest);
      for (j = 0; j < def->mounts_len; j++)
        {
          if (def->mounts[j]->type == NULL || strcmp (def->mounts[j]->type, "tmpfs") != 0)
            continue;
          size_t mount_len = strlen (def->mounts[j]->destination);
          if (mount_len < dest_len && dest[mount_len] == '/' && strncmp (dest, def->mounts[j]->destination, mount_len) == 0)
            {
              /* This is a mountpoint which is on a tmpfs.*/
              on_tmpfs = true;
              break;
            }
        }

      if (on_tmpfs)
        continue;

      /* For bind mounts check if the source is a file or a directory. */
      if (is_bind_mount (def->mounts[i], NULL, &nofollow))
        {
          if (nofollow)
            return crun_make_error (err, 0, "CRIU does not support `src-nofollow` for bind mounts");

          is_dir = crun_dir_p (def->mounts[i]->source, false, err);
          if (UNLIKELY (is_dir < 0))
            return is_dir;
        }

      root_fd = open (root, O_RDONLY | O_CLOEXEC);
      if (UNLIKELY (root_fd == -1))
        return crun_make_error (err, errno, "error opening container root directory `%s`", root);

      if (is_dir)
        {
          int ret;

          ret = crun_safe_ensure_directory_at (root_fd, root, dest, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          int ret;

          ret = crun_safe_ensure_file_at (root_fd, root, dest, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      /* Mount a bind mount source now, so that the mountpoints of the
       * mounts inside it (e.g. a nested bind mount) are created in the
       * source, where CRIU expects them.  This also happens during the
       * initial container creation, as the mounts are done in order.  */
      if (is_bind_mount (def->mounts[i], NULL, &nofollow))
        {
          cleanup_close int dst_fd = -1;
          proc_fd_path_t fd_path;

          dst_fd = safe_openat (root_fd, root, dest, O_PATH | O_CLOEXEC, 0, err);
          if (UNLIKELY (dst_fd < 0))
            return dst_fd;

          /* Not recursive: the source might contain ROOT itself (e.g. when
           * it is the bundle directory), and it is not needed anyway.  */
          get_proc_self_fd_path (fd_path, dst_fd);
          if (UNLIKELY (mount (def->mounts[i]->source, fd_path, NULL, MS_BIND, NULL) < 0))
            return crun_make_error (err, errno, "bind mount `%s` to `%s`", def->mounts[i]->source, dest);

          mounted[(*n_mounted)++] = dest;
        }
    }

  return 0;
}

/* Move the current process back to CGROUPS, as read from /proc/self/cgroup.
   A failure is not fatal, so only warn about it.  */
static void
move_back_to_cgroups (const char *cgroups)
{
  libcrun_error_t tmp_err = NULL;

  if (UNLIKELY (libcrun_move_self_to_cgroups (cgroups, &tmp_err) < 0))
    {
      libcrun_warning ("cannot move back to the original cgroup: %s", tmp_err->msg);
      crun_error_release (&tmp_err);
    }
}

/* Ask CRIU to restore from a throw-away process, which first joins CGROUP_PATH,
   when it is set, so that the tasks CRIU creates are placed there.

   It is used when the calling process must be left alone: it is neither moved
   to the container cgroup, so there is nothing to undo once the restore is
   over, nor does it become the parent of the container, as the restored
   process tree is a sibling of CRIU, hence a child of the process calling
   criu_restore_child().

   The child is kept as small as possible, as it shares the memory with the
   caller.  This is a separate function so that no variable of the caller is
   live across the vfork.  */
static int
criu_restore_child_in_cgroup (const char *cgroup_path, int *criu_ret, libcrun_error_t *err)
{
  int wait_status = 0;
  pid_t pid;
  int ret;

  *criu_ret = -1;

  /* Must be vfork: the child shares our memory space, so both *criu_ret and
     the error it creates are visible here once it is gone.  */
  pid = vfork ();
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "vfork");

  if (pid == 0)
    {
      if (! is_empty_string (cgroup_path))
        {
          ret = libcrun_move_process_to_cgroup (0, 0, cgroup_path, false, err);
          if (UNLIKELY (ret < 0))
            _safe_exit (EXIT_FAILURE);
        }

      *criu_ret = libcriu_wrapper->criu_restore_child ();
      _safe_exit (EXIT_SUCCESS);
    }

  ret = waitpid_ignore_stopped (pid, &wait_status, 0);
  if (UNLIKELY (ret < 0))
    {
      /* The caller might have reaped the child already, e.g. when it ignores
         SIGCHLD.  Its result is still visible, so use it.  */
      if (errno != ECHILD)
        return crun_make_error (err, errno, "waitpid for the CRIU restore process");
      return 0;
    }

  ret = get_process_exit_status (wait_status);
  if (UNLIKELY (ret != EXIT_SUCCESS))
    {
      /* The child creates the error in the shared memory space, do not
         overwrite it with crun_make_error().  */
      if (*err == NULL)
        return crun_make_error (err, 0, "the CRIU restore process exited with status %d", ret);
      return -1;
    }

  return 0;
}

/* Recreate the mountpoints which do not exist in the container rootfs
 * mounted at ROOT, the same way it is done on the container creation.  */
static int
prepare_restore_mounts (runtime_spec_schema_config_schema *def, char *root, libcrun_error_t *err)
{
  cleanup_free const char **mounted = xmalloc0 (sizeof (char *) * (def->mounts_len + 1));
  cleanup_close int root_fd = -1;
  size_t n_mounted = 0;
  int ret;

  ret = prepare_restore_mounts_internal (def, root, mounted, &n_mounted, err);

  /* The bind mounts done above are only needed to create the mountpoints,
   * and CRIU restores the mounts itself, so undo them, in reverse order. */
  if (n_mounted > 0)
    root_fd = open (root, O_PATH | O_CLOEXEC);
  while (root_fd >= 0 && n_mounted > 0)
    {
      libcrun_error_t tmp_err = NULL;
      const char *dest = mounted[--n_mounted];
      cleanup_close int dst_fd = -1;
      proc_fd_path_t fd_path;

      dst_fd = safe_openat (root_fd, root, dest, O_PATH | O_CLOEXEC, 0, &tmp_err);
      if (UNLIKELY (dst_fd < 0))
        {
          crun_error_release (&tmp_err);
          continue;
        }
      get_proc_self_fd_path (fd_path, dst_fd);
      if (UNLIKELY (umount2 (fd_path, MNT_DETACH) < 0 && ret >= 0))
        ret = crun_make_error (err, errno, "unmount `%s`", dest);
    }

  return ret;
}

int
libcrun_container_restore_linux_criu (libcrun_container_status_t *status, libcrun_container_t *container,
                                      libcrun_checkpoint_restore_t *cr_options, unsigned int options,
                                      libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_wrapper struct libcriu_wrapper_s *wrapper = NULL;
  cleanup_close int inherit_new_net_fd = -1;
  cleanup_close int inherit_new_pid_fd = -1;
  cleanup_close int image_fd = -1;
  cleanup_free char *root = NULL;
  cleanup_free char *bundle_cleanup = NULL;
  cleanup_free char *own_cgroups = NULL;
  cleanup_close int work_fd = -1;
  int cgroup_mode;
  int criu_ret;
  int ret_out;
  size_t i;
  int ret;

  ret = load_wrapper (&wrapper, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (geteuid ())
    return crun_make_error (err, 0, "restoring requires root");

  ret = libcriu_wrapper->criu_init_opts ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU init failed with %d", ret);

  ret = validate_criu_version (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (cr_options->image_path == NULL))
    return crun_make_error (err, 0, "image path not set");

  image_fd = open (cr_options->image_path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (image_fd == -1))
    return crun_make_error (err, errno, "error opening checkpoint directory `%s`", cr_options->image_path);

  libcriu_wrapper->criu_set_images_dir_fd (image_fd);

  /* Load descriptors.json to tell CRIU where those FDs should be connected to. */
  {
    cleanup_free char *descriptors_path = NULL;
    cleanup_free char *buffer = NULL;
    json_object *doc = NULL;

    ret = append_paths (&descriptors_path, err, cr_options->image_path, DESCRIPTORS_FILENAME, NULL);
    if (UNLIKELY (ret < 0))
      return ret;

    ret = read_all_file (descriptors_path, &buffer, NULL, err);
    if (UNLIKELY (ret < 0))
      return ret;

    /* descriptors.json contains a JSON array with strings
     * telling where 0, 1 and 2 have been initially been
     * pointing to. For each descriptor which points to
     * a pipe 'pipe:' we tell CRIU to reconnect that pipe
     * to the corresponding FD to have (especially) stdout
     * and stderr being correctly redirected. */
    ret = parse_json_file (&doc, buffer, NULL, err);
    if (UNLIKELY (ret < 0))
      return ret;

    if (json_object_is_type (doc, json_type_array))
      {
        size_t i, len = json_object_array_length (doc);

        /* len will probably always be 3 as crun is currently only
         * recording the destination of FD 0, 1 and 2. */
        for (i = 0; i < len; ++i)
          {
            json_object *s = json_object_array_get_idx (doc, i);
            if (s && json_object_is_type (s, json_type_string))
              {
                const char *str = json_object_get_string (s);
                if (has_prefix (str, "pipe:"))
                  libcriu_wrapper->criu_add_inherit_fd (i, str);
              }
          }
      }
    json_object_put (doc);
  }

  ret = setup_criu_work_dir (cr_options, &work_fd, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (cr_options->lsm_profile != NULL)
    {
      ret = libcriu_wrapper->criu_set_lsm_profile (cr_options->lsm_profile);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, -ret, "error setting LSM profile to `%s`", cr_options->lsm_profile);
    }

  if (cr_options->lsm_mount_context != NULL)
    {
      ret = libcriu_wrapper->criu_set_lsm_mount_context (cr_options->lsm_mount_context);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, -ret, "error setting LSM mount context to `%s`", cr_options->lsm_mount_context);
    }

  /* do realpath on root */
  bundle_cleanup = realpath (status->bundle, NULL);
  if (UNLIKELY (bundle_cleanup == NULL))
    bundle_cleanup = xstrdup (status->bundle);

  /* Tell CRIU about external bind mounts. */
  for (i = 0; i < def->mounts_len; i++)
    {
      bool nofollow = false;
      if (is_bind_mount (def->mounts[i], NULL, &nofollow))
        {
          /* We need to resolve mount destination inside container's root for CRIU to handle. */
          char buf[PATH_MAX];
          const char *dest_in_root;
          const char *source = def->mounts[i]->source;
          cleanup_free char *abs_source = NULL;

          if (nofollow)
            return crun_make_error (err, 0, "CRIU does not support `src-nofollow` for bind mounts");

          dest_in_root = chroot_realpath (status->rootfs, def->mounts[i]->destination, buf);
          if (UNLIKELY (dest_in_root == NULL))
            return crun_make_error (err, errno, "unable to resolve external bind mount destination `%s` under rootfs", def->mounts[i]->destination);

          /* When the rootfs is "/" or not set, chroot_realpath returns the
             path unchanged, so strip the prefix only when it is there.  */
          if (has_prefix (dest_in_root, status->rootfs))
            dest_in_root += safe_strlen (status->rootfs);

          /* A relative source is relative to the bundle, while CRIU would
             resolve it relative to its own working directory.  */
          if (source && source[0] != '/')
            {
              ret = append_paths (&abs_source, err, bundle_cleanup, source, NULL);
              if (UNLIKELY (ret < 0))
                return ret;
              source = abs_source;
            }

          ret = libcriu_wrapper->criu_add_ext_mount (dest_in_root, source);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, -ret, "CRIU: failed adding external mount to `%s`", source);
        }
    }

  ret = register_masked_paths_mounts (def, container, libcriu_wrapper, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Mount the container rootfs for CRIU. */
  ret = append_paths (&root, err, bundle_cleanup, "criu-root", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = mkdir (root, 0755);
  if (UNLIKELY (ret == -1))
    return crun_make_error (err, errno, "error creating restore directory `%s`", root);

  ret = mount (status->rootfs, root, NULL, MS_BIND | MS_REC, NULL);
  if (UNLIKELY (ret == -1))
    {
      ret = crun_make_error (err, errno, "error mounting restore directory `%s`", root);
      goto out;
    }

  /* During initial container creation, crun will create mountpoints
   * defined in config.json if they do not exist. If we are restoring
   * we need to make sure these mountpoints also exist.
   * This is not perfect, as this means crun will modify a rootfs
   * even if it marked as read-only, but runc already modifies
   * the rootfs in the same way. */

  ret = prepare_restore_mounts (def, root, err);
  if (UNLIKELY (ret < 0))
    goto out_umount;

  ret = libcriu_wrapper->criu_set_root (root);
  if (UNLIKELY (ret != 0))
    {
      ret = crun_make_error (err, -ret, "error setting CRIU root to `%s`", root);
      goto out_umount;
    }

  /* If a namespace defined in config.json we are telling
   * CRIU use that namespace when restoring the process tree.
   *
   * CRIU expects the information about the namespace like this:
   * --inherit-fd fd[<fd>]:<key>
   * The <key> needs to be the same as during checkpointing (extRootNetNS). */
  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      const int open_flags_for_inherit = O_RDONLY; /* Cannot be O_CLOEXEC as it is passed to the child process. */
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        {
          ret = crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);
          goto out_umount;
        }

      if (value == CLONE_NEWNET && def->linux->namespaces[i]->path != NULL)
        {
          inherit_new_net_fd = open (def->linux->namespaces[i]->path, open_flags_for_inherit);
          if (UNLIKELY (inherit_new_net_fd < 0))
            {
              ret = crun_make_error (err, errno, "unable to open(): `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_add_inherit_fd (inherit_new_net_fd, CRIU_EXT_NETNS);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding fd");
              goto out_umount;
            }
        }

      if (value == CLONE_NEWPID && def->linux->namespaces[i]->path != NULL)
        {
          inherit_new_pid_fd = open (def->linux->namespaces[i]->path, open_flags_for_inherit);
          if (UNLIKELY (inherit_new_pid_fd < 0))
            {
              ret = crun_make_error (err, errno, "unable to open(): `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_add_inherit_fd (inherit_new_pid_fd, CRIU_EXT_PIDNS);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding fd");
              goto out_umount;
            }
        }

#  ifdef CRIU_JOIN_NS_SUPPORT
      if (value == CLONE_NEWTIME && def->linux->namespaces[i]->path != NULL)
        {
          if (libcriu_wrapper->criu_join_ns_add == NULL)
            {
              ret = crun_make_error (err, 0, "shared time namespace restore is supported in CRIU >= 3.16.1");
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_join_ns_add ("time", def->linux->namespaces[i]->path, NULL);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }
        }

      if (value == CLONE_NEWIPC && def->linux->namespaces[i]->path != NULL)
        {
          if (libcriu_wrapper->criu_join_ns_add == NULL)
            {
              ret = crun_make_error (err, 0, "shared ipc namespace restore is supported in CRIU >= 3.16.1");
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_join_ns_add ("ipc", def->linux->namespaces[i]->path, NULL);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }
        }

      if (value == CLONE_NEWUTS && def->linux->namespaces[i]->path != NULL)
        {
          if (libcriu_wrapper->criu_join_ns_add == NULL)
            {
              ret = crun_make_error (err, 0, "shared uts namespace restore is supported in CRIU >= 3.16.1");
              goto out_umount;
            }

          ret = libcriu_wrapper->criu_join_ns_add ("uts", def->linux->namespaces[i]->path, NULL);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, -ret, "CRIU: failed adding external namespace `%s`", def->linux->namespaces[i]->path);
              goto out_umount;
            }
        }
#  endif
    }

  /* Set up CRIU config file */
  ret = handle_criu_config_file (container, err);
  if (UNLIKELY (ret < 0))
    goto out_umount;

  /* Tell CRIU if cgroup v1 needs to be handled. */
  ret = restore_cgroup_v1_mount (def, err);
  if (UNLIKELY (ret < 0))
    goto out_umount;

  console_socket = cr_options->console_socket;
  libcriu_wrapper->criu_set_notify_cb (criu_notify);

  /* Set boolean options . */
  libcriu_wrapper->criu_set_ext_unix_sk (cr_options->ext_unix_sk);
  libcriu_wrapper->criu_set_shell_job (cr_options->shell_job);
  libcriu_wrapper->criu_set_tcp_established (cr_options->tcp_established);
  libcriu_wrapper->criu_set_tcp_close (cr_options->tcp_close);
  libcriu_wrapper->criu_set_file_locks (cr_options->file_locks);
  libcriu_wrapper->criu_set_orphan_pts_master (true);

  if (status->cgroup_path)
    {
      cgroup_mode = libcrun_get_cgroup_mode (err);
      if (UNLIKELY (cgroup_mode < 0))
        {
          ret = cgroup_mode;
          goto out_umount;
        }

      /* With cgroup v2, the cgroup path is only meaningful for the unified
         hierarchy, so only relocate that one.  A NULL controller would make
         CRIU relocate every hierarchy the container is in, named cgroup v1
         ones included.  As CRIU dumps such a hierarchy from wherever the
         container is in it, which is its root, as crun leaves named
         hierarchies alone, every checkpoint and restore would then copy the
         whole hierarchy into itself.  */
      ret = libcriu_wrapper->criu_add_cg_root (cgroup_mode == CGROUP_MODE_UNIFIED ? "" : NULL,
                                               status->cgroup_path);
      if (UNLIKELY (ret != 0))
        {
          ret = crun_make_error (err, 0, "error setting CRIU cgroup root to `%s`", status->cgroup_path);
          goto out_umount;
        }
    }

  if (cr_options->manage_cgroups_mode == -1)
    /* Defaulting to CRIU_CG_MODE_SOFT just as runc */
    libcriu_wrapper->criu_set_manage_cgroups_mode (CRIU_CG_MODE_SOFT);
  else
    libcriu_wrapper->criu_set_manage_cgroups_mode (cr_options->manage_cgroups_mode);
  libcriu_wrapper->criu_set_manage_cgroups (true);

  if (libcriu_wrapper->criu_set_network_lock && cr_options->network_lock_method > 0)
    {
      ret = libcriu_wrapper->criu_set_network_lock (cr_options->network_lock_method);
      if (UNLIKELY (ret < 0))
        {
          ret = crun_make_error (err, 0, "CRIU: failed setting network lock");
          goto out_umount;
        }
    }

  libcriu_wrapper->criu_set_log_level (4);
  ret = libcriu_wrapper->criu_set_log_file (CRIU_RESTORE_LOG_FILE);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "error setting CRIU log file to `%s`", CRIU_RESTORE_LOG_FILE);
      goto out_umount;
    }

  /* criu_restore() returns the PID of the process of the restored process
   * tree. This PID will not be the same as status->pid if the container is
   * running in a PID namespace. But it will always be > 0. */
  if (options & LIBCRUN_RESTORE_OPTIONS_PREFORK)
    {
      /* The calling process must be left alone, so use a throw-away process.
         It must be used even when there is no cgroup to join, or the container
         would be a child of the caller.  */
      ret = criu_restore_child_in_cgroup (status->cgroup_path, &criu_ret, err);
      if (UNLIKELY (ret < 0))
        goto out_umount;

      ret = criu_ret;
    }
  else
    {
      /* Like runc does, put CRIU into the container cgroup for the time of
       * restore, so the restored tasks are created there. It is necessary in
       * the "ignore" mode, where CRIU does not deal with cgroups at all, and
       * does not hurt otherwise. As CRIU is our child, do it by moving
       * ourselves there, and move back once the restore is done. */
      if (! is_empty_string (status->cgroup_path))
        {
          ret = read_all_file (PROC_SELF_CGROUP, &own_cgroups, NULL, err);
          if (UNLIKELY (ret < 0))
            goto out_umount;

          ret = libcrun_move_process_to_cgroup (0, 0, status->cgroup_path, false, err);
          if (UNLIKELY (ret < 0))
            {
              /* Some of the cgroups might have been joined already.  */
              move_back_to_cgroups (own_cgroups);
              goto out_umount;
            }
        }

      ret = libcriu_wrapper->criu_restore_child ();

      if (own_cgroups)
        move_back_to_cgroups (own_cgroups);
    }

  if (UNLIKELY (ret <= 0))
    {
      show_criu_log (cr_options->work_path, CRIU_RESTORE_LOG_FILE);
      ret = crun_make_error (err, 0, "CRIU restoring failed: %d", ret);
      goto out_umount;
    }

  /* Update the status struct with the newly allocated PID. This will
   * be necessary later when moving the process into its cgroup. */
  status->pid = ret;

  ret = libcrun_save_external_descriptors (container, ret, err);

out_umount:
  ret_out = umount (root);
  if (UNLIKELY (ret_out == -1))
    {
      int saved_errno = errno;
      rmdir (root);
      if (ret < 0)
        return crun_error_wrap (err, "error unmounting restore directory `%s`", root);
      else
        return crun_make_error (err, saved_errno, "error unmounting restore directory `%s`", root);
    }
out:
  ret_out = rmdir (root);
  if (UNLIKELY (ret < 0))
    return ret;
  if (UNLIKELY (ret_out == -1))
    return crun_make_error (err, errno, "error removing restore directory `%s`", root);
  return ret;
}
#endif
