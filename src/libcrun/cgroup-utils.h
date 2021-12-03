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
#ifndef CGROUP_UTILS_H
#define CGROUP_UTILS_H

#include "container.h"
#include "cgroup.h"
#include <unistd.h>

int libcrun_move_process_to_cgroup (pid_t pid, pid_t init_pid, char *path, libcrun_error_t *err);

int libcrun_cgroups_create_symlinks (int dirfd, libcrun_error_t *err);

int libcrun_get_current_unified_cgroup (char **path, libcrun_error_t *err);

int libcrun_get_cgroup_mode (libcrun_error_t *err);

#endif
