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

#ifdef HAVE_CRIU

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

#  define CRIU_CHECKPOINT_LOG_FILE "dump.log"
#  define CRIU_RESTORE_LOG_FILE "restore.log"
#  define DESCRIPTORS_FILENAME "descriptors.json"

#  define CRIU_EXT_NETNS "extRootNetNS"
#  define CRIU_EXT_PIDNS "extRootPidNS"

#  ifndef CLONE_NEWTIME
#    define CLONE_NEWTIME 0x00000080 /* New time namespace */
#  endif

static const char *console_socket = NULL;

static int
criu_notify (char *action, __attribute__ ((unused)) criu_notify_arg_t na)
{
  if (strncmp (action, "orphan-pts-master", 17) == 0)
    {
      /* CRIU sends us the master FD via the 'orphan-pts-master'
       * callback and we are passing it on to the '--console-socket'
       * if it exists. */
      cleanup_close int console_socket_fd = -1;
      int master_fd;
      int ret;

      if (! console_socket)
        return 0;
      master_fd = criu_get_orphan_pts_master_fd ();

      console_socket_fd = open_unix_domain_client_socket (console_socket, 0, NULL);
      if (UNLIKELY (console_socket_fd < 0))
        return console_socket_fd;
      ret = send_fd_to_socket (console_socket_fd, master_fd, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
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
      if (strcmp (def->mounts[i]->type, "cgroup") == 0)
        {
          has_cgroup_mount = true;
          break;
        }
    }

  if (! has_cgroup_mount)
    return 0;

  ret = read_all_file ("/proc/self/cgroup", &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, 0, "invalid content from /proc/self/cgroup");

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *destination = NULL;
      cleanup_free char *source = NULL;
      char *subsystem;
      char *subpath;
      char *it;

      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      if (subsystem[0] == '\0')
        continue;

      it = strstr (subsystem, "name=");
      if (it)
        subsystem = it + 5;

      if (strcmp (subsystem, "net_prio,net_cls") == 0)
        subsystem = "net_cls,net_prio";
      if (strcmp (subsystem, "cpuacct,cpu") == 0)
        subsystem = "cpu,cpuacct";

      ret = append_paths (&source, err, CGROUP_ROOT, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&destination, err, source, subpath, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      criu_add_ext_mount (source, destination);
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
      if (strcmp (def->mounts[i]->type, "cgroup") == 0)
        {
          has_cgroup_mount = true;
          break;
        }
    }

  if (! has_cgroup_mount)
    return 0;

  ret = read_all_file ("/proc/self/cgroup", &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (content == NULL || content[0] == '\0'))
    return crun_make_error (err, 0, "invalid content from /proc/self/cgroup");

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      cleanup_free char *source_path = NULL;
      char *subsystem;
      char *subpath;
      char *it;

      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      if (subsystem[0] == '\0')
        continue;

      it = strstr (subsystem, "name=");
      if (it)
        subsystem = it + 5;

      if (strcmp (subsystem, "net_prio,net_cls") == 0)
        subsystem = "net_cls,net_prio";
      if (strcmp (subsystem, "cpuacct,cpu") == 0)
        subsystem = "cpu,cpuacct";

      ret = append_paths (&source_path, err, CGROUP_ROOT, subsystem, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      criu_add_ext_mount (source_path, source_path);
    }

  return 0;
}

int
libcrun_container_checkpoint_linux_criu (libcrun_container_status_t *status, libcrun_container_t *container,
                                         libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_free char *descriptors_path = NULL;
  cleanup_free char *freezer_path = NULL;
  cleanup_free char *path = NULL;
  cleanup_close int image_fd = -1;
  cleanup_close int work_fd = -1;
  int cgroup_mode;
  size_t i;
  int ret;

  if (geteuid ())
    return crun_make_error (err, 0, "Checkpointing requires root");

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

  ret = criu_init_opts ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU init failed with %d", ret);

  if (UNLIKELY (cr_options->image_path == NULL))
    return crun_make_error (err, 0, "image path not set");

  ret = mkdir (cr_options->image_path, 0700);
  if (UNLIKELY ((ret == -1) && (errno != EEXIST)))
    return crun_make_error (err, errno, "error creating checkpoint directory %s", cr_options->image_path);

  image_fd = open (cr_options->image_path, O_DIRECTORY);
  if (UNLIKELY (image_fd == -1))
    return crun_make_error (err, errno, "error opening checkpoint directory %s", cr_options->image_path);

  criu_set_images_dir_fd (image_fd);

  /* descriptors.json is needed during restore to correctly
   * reconnect stdin, stdout, stderr. */
  ret = append_paths (&descriptors_path, err, cr_options->image_path, DESCRIPTORS_FILENAME, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = write_file (descriptors_path, status->external_descriptors, strlen (status->external_descriptors), err);
  if (UNLIKELY (ret < 0))
    return crun_error_wrap (err, "error saving CRIU descriptors file");

  /* work_dir is the place CRIU will put its logfiles. If not explicitly set,
   * CRIU will put the logfiles into the images_dir from above. No need for
   * crun to set it if the user has not selected a specific directory. */
  if (cr_options->work_path != NULL)
    {
      work_fd = open (cr_options->work_path, O_DIRECTORY);
      if (UNLIKELY (work_fd == -1))
        return crun_make_error (err, errno, "error opening CRIU work directory %s", cr_options->work_path);

      criu_set_work_dir_fd (work_fd);
    }
  else
    {
      /* This is only for the error message later. */
      cr_options->work_path = cr_options->image_path;
    }

  /* The main process of the container is the process CRIU will checkpoint
   * and all of its children. */
  criu_set_pid (status->pid);

  ret = append_paths (&path, err, status->bundle, status->rootfs, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = criu_set_root (path);
  if (UNLIKELY (ret != 0))
    return crun_make_error (err, 0, "error setting CRIU root to %s", path);

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  /* For cgroup v1 we need to tell CRIU to handle all cgroup mounts as external mounts. */
  if (cgroup_mode != CGROUP_MODE_UNIFIED)
    {
      ret = checkpoint_cgroup_v1_mount (def, err);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, 0, "error handling cgroup v1 mounts");
    }

  /* Tell CRIU about external bind mounts. */
  for (i = 0; i < def->mounts_len; i++)
    {
      size_t j;

      for (j = 0; j < def->mounts[i]->options_len; j++)
        {
          if (strcmp (def->mounts[i]->options[j], "bind") == 0 || strcmp (def->mounts[i]->options[j], "rbind") == 0)
            {
              criu_add_ext_mount (def->mounts[i]->destination, def->mounts[i]->destination);
              break;
            }
        }
    }

  for (i = 0; i < def->linux->masked_paths_len; i++)
    {
      struct stat statbuf;
      ret = stat (def->linux->masked_paths[i], &statbuf);
      if (ret == 0 && S_ISREG (statbuf.st_mode))
        criu_add_ext_mount (def->linux->masked_paths[i], def->linux->masked_paths[i]);
    }

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
      cleanup_free char *external = NULL;
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);

      if (value == CLONE_NEWNET && def->linux->namespaces[i]->path != NULL)
        {
          struct stat statbuf;
          ret = stat (def->linux->namespaces[i]->path, &statbuf);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "unable to stat(): `%s`", def->linux->namespaces[i]->path);

          xasprintf (&external, "net[%ld]:" CRIU_EXT_NETNS, statbuf.st_ino);
          criu_add_external (external);
        }

      if (value == CLONE_NEWPID && def->linux->namespaces[i]->path != NULL)
        {
          struct stat statbuf;
          ret = stat (def->linux->namespaces[i]->path, &statbuf);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "unable to stat(): `%s`", def->linux->namespaces[i]->path);

          xasprintf (&external, "pid[%ld]:" CRIU_EXT_PIDNS, statbuf.st_ino);
          criu_add_external (external);
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

  ret = criu_set_freeze_cgroup (freezer_path);
  if (UNLIKELY (ret != 0))
    return crun_make_error (err, ret, "CRIU: failed setting freezer %d", ret);

  /* Set boolean options . */
  criu_set_leave_running (cr_options->leave_running);
  criu_set_ext_unix_sk (cr_options->ext_unix_sk);
  criu_set_shell_job (cr_options->shell_job);
  criu_set_tcp_established (cr_options->tcp_established);
  criu_set_file_locks (cr_options->file_locks);
  criu_set_orphan_pts_master (true);
  criu_set_manage_cgroups (true);

  /* Set up logging. */
  criu_set_log_level (4);
  criu_set_log_file (CRIU_CHECKPOINT_LOG_FILE);
  ret = criu_dump ();
  if (UNLIKELY (ret != 0))
    return crun_make_error (err, 0,
                            "CRIU checkpointing failed %d.  Please check CRIU logfile %s/%s",
                            ret, cr_options->work_path, CRIU_CHECKPOINT_LOG_FILE);

  return 0;
}

static int
prepare_restore_mounts (runtime_spec_schema_config_schema *def, char *root, libcrun_error_t *err)
{
  uint32_t i;

  /* Go through all mountpoints to be able to recreate missing mountpoints. */
  for (i = 0; i < def->mounts_len; i++)
    {
      char *dest = def->mounts[i]->destination;
      char *type = def->mounts[i]->type;
      cleanup_close int root_fd = -1;
      bool on_tmpfs = false;
      int is_dir = 1;
      size_t j;

      /* cgroup restore should be handled by CRIU itself */
      if (strcmp (type, "cgroup") == 0 || strcmp (type, "cgroup2") == 0)
        continue;

      /* Check if the mountpoint is on a tmpfs. CRIU restores
       * all tmpfs. We do need to recreate directories on a tmpfs. */
      for (j = 0; j < def->mounts_len; j++)
        {
          cleanup_free char *dest_loop = NULL;

          xasprintf (&dest_loop, "%s/", def->mounts[j]->destination);
          if (strncmp (dest, dest_loop, strlen (dest_loop)) == 0 && strcmp (def->mounts[j]->type, "tmpfs") == 0)
            {
              /* This is a mountpoint which is on a tmpfs.*/
              on_tmpfs = true;
              break;
            }
        }

      if (on_tmpfs)
        continue;

      /* For bind mounts check if the source is a file or a directory. */
      for (j = 0; j < def->mounts[i]->options_len; j++)
        {
          const char *opt = def->mounts[i]->options[j];
          if (strcmp (opt, "bind") == 0 || strcmp (opt, "rbind") == 0)
            {
              is_dir = crun_dir_p (def->mounts[i]->source, false, err);
              if (UNLIKELY (is_dir < 0))
                return is_dir;
              break;
            }
        }

      root_fd = open (root, O_RDONLY | O_CLOEXEC);
      if (UNLIKELY (root_fd == -1))
        return crun_make_error (err, errno, "error opening container root directory %s", root);

      if (is_dir)
        {
          int ret;

          ret = crun_safe_ensure_directory_at (root_fd, root, strlen (root), dest, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          int ret;

          ret = crun_safe_ensure_file_at (root_fd, root, strlen (root), dest, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  return 0;
}

int
libcrun_container_restore_linux_criu (libcrun_container_status_t *status, libcrun_container_t *container,
                                      libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close int inherit_new_net_fd = -1;
  cleanup_close int inherit_new_pid_fd = -1;
  cleanup_close int image_fd = -1;
  cleanup_free char *root = NULL;
  cleanup_close int work_fd = -1;
  int ret_out;
  size_t i;
  int ret;

  if (geteuid ())
    return crun_make_error (err, 0, "Restoring requires root");

  ret = criu_init_opts ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "CRIU init failed with %d", ret);

  if (UNLIKELY (cr_options->image_path == NULL))
    return crun_make_error (err, 0, "image path not set");

  image_fd = open (cr_options->image_path, O_DIRECTORY);
  if (UNLIKELY (image_fd == -1))
    return crun_make_error (err, errno, "error opening checkpoint directory %s", cr_options->image_path);

  criu_set_images_dir_fd (image_fd);

  /* Load descriptors.json to tell CRIU where those FDs should be connected to. */
  {
    cleanup_free char *descriptors_path = NULL;
    cleanup_free char *buffer = NULL;
    char err_buffer[256];
    yajl_val tree;

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
    tree = yajl_tree_parse (buffer, err_buffer, sizeof (err_buffer));
    if (UNLIKELY (tree == NULL))
      return crun_make_error (err, 0, "cannot parse descriptors file %s", DESCRIPTORS_FILENAME);

    if (tree && YAJL_IS_ARRAY (tree))
      {
        size_t i, len = tree->u.array.len;

        /* len will probably always be 3 as crun is currently only
         * recording the destination of FD 0, 1 and 2. */
        for (i = 0; i < len; ++i)
          {
            yajl_val s = tree->u.array.values[i];
            if (s && YAJL_IS_STRING (s))
              {
                char *str = YAJL_GET_STRING (s);
                if (has_prefix (str, "pipe:"))
                  criu_add_inherit_fd (i, str);
              }
          }
      }
    yajl_tree_free (tree);
  }

  /* work_dir is the place CRIU will put its logfiles. If not explicitly set,
   * CRIU will put the logfiles into the images_dir from above. No need for
   * crun to set it if the user has not selected a specific directory. */
  if (cr_options->work_path != NULL)
    {
      work_fd = open (cr_options->work_path, O_DIRECTORY);
      if (UNLIKELY (work_fd == -1))
        return crun_make_error (err, errno, "error opening CRIU work directory %s", cr_options->work_path);

      criu_set_work_dir_fd (work_fd);
    }
  else
    {
      /* This is only for the error message later. */
      cr_options->work_path = cr_options->image_path;
    }

  /* Tell CRIU about external bind mounts. */
  for (i = 0; i < def->mounts_len; i++)
    {
      size_t j;

      for (j = 0; j < def->mounts[i]->options_len; j++)
        {
          if (strcmp (def->mounts[i]->options[j], "bind") == 0 || strcmp (def->mounts[i]->options[j], "rbind") == 0)
            {
              criu_add_ext_mount (def->mounts[i]->destination, def->mounts[i]->source);
              break;
            }
        }
    }

  for (i = 0; i < def->linux->masked_paths_len; i++)
    {
      struct stat statbuf;
      ret = stat (def->linux->masked_paths[i], &statbuf);
      if (ret == 0 && S_ISREG (statbuf.st_mode))
        criu_add_ext_mount (def->linux->masked_paths[i], "/dev/null");
    }

  /* Mount the container rootfs for CRIU. */
  ret = append_paths (&root, err, status->bundle, "criu-root", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = mkdir (root, 0755);
  if (UNLIKELY (ret == -1))
    return crun_make_error (err, errno, "error creating restore directory %s", root);
  /* do realpath on root */
  ret = mount (status->rootfs, root, NULL, MS_BIND | MS_REC, NULL);
  if (UNLIKELY (ret == -1))
    {
      ret = crun_make_error (err, errno, "error mounting restore directory %s", root);
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

  ret = criu_set_root (root);
  if (UNLIKELY (ret != 0))
    {
      ret = crun_make_error (err, 0, "error setting CRIU root to %s", root);
      goto out_umount;
    }

#  ifdef CRIU_JOIN_NS_SUPPORT
  /* criu_join_ns_add() API was introduced with CRIU version 3.16.1
   * Here we check if this API is available at build time to support
   * compiling with older version of CRIU, and at runtime to support
   * running crun with older versions of libcriu.so.2.
   */
  bool join_ns_support = criu_check_version (31601) == 1;
#  endif

  /* If a namespace defined in config.json we are telling
   * CRIU use that namespace when restoring the process tree.
   *
   * CRIU expects the information about the namespace like this:
   * --inherit-fd fd[<fd>]:<key>
   * The <key> needs to be the same as during checkpointing (extRootNetNS). */
  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: `%s`", def->linux->namespaces[i]->type);

      if (value == CLONE_NEWNET && def->linux->namespaces[i]->path != NULL)
        {
          inherit_new_net_fd = open (def->linux->namespaces[i]->path, O_RDONLY);
          if (UNLIKELY (inherit_new_net_fd < 0))
            return crun_make_error (err, errno, "unable to open(): `%s`", def->linux->namespaces[i]->path);

          criu_add_inherit_fd (inherit_new_net_fd, CRIU_EXT_NETNS);
        }

      if (value == CLONE_NEWPID && def->linux->namespaces[i]->path != NULL)
        {
          inherit_new_pid_fd = open (def->linux->namespaces[i]->path, O_RDONLY);
          if (UNLIKELY (inherit_new_pid_fd < 0))
            return crun_make_error (err, errno, "unable to open(): `%s`", def->linux->namespaces[i]->path);

          criu_add_inherit_fd (inherit_new_pid_fd, CRIU_EXT_PIDNS);
        }

#  ifdef CRIU_JOIN_NS_SUPPORT
      if (value == CLONE_NEWTIME && def->linux->namespaces[i]->path != NULL)
        {
          if (join_ns_support)
            criu_join_ns_add ("time", def->linux->namespaces[i]->path, NULL);
          else
            return crun_make_error (err, 0, "Shared time namespace restore is supported in CRIU >= 3.16.1");
        }

      if (value == CLONE_NEWIPC && def->linux->namespaces[i]->path != NULL)
        {
          if (join_ns_support)
            criu_join_ns_add ("ipc", def->linux->namespaces[i]->path, NULL);
          else
            return crun_make_error (err, 0, "Shared ipc namespace restore is supported in CRIU >= 3.16.1");
        }

      if (value == CLONE_NEWUTS && def->linux->namespaces[i]->path != NULL)
        {
          if (join_ns_support)
            criu_join_ns_add ("uts", def->linux->namespaces[i]->path, NULL);
          else
            return crun_make_error (err, 0, "Shared uts namespace restore is supported in CRIU >= 3.16.1");
        }
#  endif
    }

  /* Tell CRIU if cgroup v1 needs to be handled. */
  ret = restore_cgroup_v1_mount (def, err);
  if (UNLIKELY (ret < 0))
    goto out_umount;

  console_socket = cr_options->console_socket;
  criu_set_notify_cb (criu_notify);

  /* Set boolean options . */
  criu_set_ext_unix_sk (cr_options->ext_unix_sk);
  criu_set_shell_job (cr_options->shell_job);
  criu_set_tcp_established (cr_options->tcp_established);
  criu_set_file_locks (cr_options->file_locks);
  criu_set_orphan_pts_master (true);
  criu_set_manage_cgroups (true);

  criu_set_log_level (4);
  criu_set_log_file (CRIU_RESTORE_LOG_FILE);
  ret = criu_restore_child ();

  /* criu_restore() returns the PID of the process of the restored process
   * tree. This PID will not be the same as status->pid if the container is
   * running in a PID namespace. But it will always be > 0. */

  if (UNLIKELY (ret <= 0))
    {
      ret = crun_make_error (err, 0,
                             "CRIU restoring failed %d.  Please check CRIU logfile %s/%s",
                             ret, cr_options->work_path, CRIU_RESTORE_LOG_FILE);
      goto out_umount;
    }

  /* Update the status struct with the newly allocated PID. This will
   * be necessary later when moving the process into its cgroup. */
  status->pid = ret;

  if (LIKELY (ret > 0))
    ret = libcrun_save_external_descriptors (container, ret, err);

out_umount:
  ret_out = umount (root);
  if (UNLIKELY (ret_out == -1))
    {
      rmdir (root);
      return crun_make_error (err, errno, "error unmounting restore directory %s", root);
    }
out:
  ret_out = rmdir (root);
  if (UNLIKELY (ret == -1))
    return ret;
  if (UNLIKELY (ret_out == -1))
    return crun_make_error (err, errno, "error removing restore directory %s", root);
  return ret;
}
#endif
