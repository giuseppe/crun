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
#ifndef SECCOMP_NOTIFY_H
# define SECCOMP_NOTIFY_H

# include <config.h>
# include "error.h"

# if !(HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES)
#  define SECCOMP_NOTIFY_SKIP_TYPEDEF
# endif
# include "seccomp_notify_plugin.h"

struct seccomp_notify_context_s;

LIBCRUN_PUBLIC int libcrun_load_seccomp_notify_plugins (struct seccomp_notify_context_s **out, const char *plugins, struct libcrun_load_seccomp_notify_conf_s *conf, libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_seccomp_notify_plugins (struct seccomp_notify_context_s *ctx, int seccomp_fd, libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_free_seccomp_notify_plugins (struct seccomp_notify_context_s *ctx, libcrun_error_t *err);

# define cleanup_seccomp_notify_context __attribute__((cleanup (cleanup_seccomp_notify_pluginsp)))
void cleanup_seccomp_notify_pluginsp (void *p);

#endif
