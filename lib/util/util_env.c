/*
   Unix SMB/CIFS implementation.
   environtment variable handle for execle
   Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Environment variable handling for execle(2)
 * ====================================================================== */

/* Samba common include file */
#include "includes.h"

#include "util_env.h"

#define strn_eq(s1, s2, n)	\
	((strncmp((s1), (s2), (n)) == 0) ? true : false)

#define ENV_SIZE_CHUNK 32

env_struct *env_new(TALLOC_CTX *ctx)
{
	env_struct *env_h = talloc_zero(ctx, env_struct);
	if (!env_h) {
		DEBUG(0, ("talloc_zero failed\n"));
		goto env_init_failed;
	}

	env_h->env_num = 0;
	env_h->env_size = ENV_SIZE_CHUNK;
	env_h->env_list = talloc_array(env_h, char *, env_h->env_size);
	if (!env_h->env_list) {
		DEBUG(0, ("TALLOC_ARRAY failed\n"));
		goto env_init_failed;
	}

	env_h->env_list[0] = NULL;

	return env_h;

env_init_failed:
	TALLOC_FREE(env_h);
	return NULL;
}

char * const *env_list(env_struct *env_h)
{
	return env_h->env_list;
}

int env_set(env_struct *env_h, const char *name, const char *value)
{
	size_t name_len = strlen(name);
	/* strlen("name=value") */
	size_t env_len = name_len + 1 + strlen(value);
	char **env_p;

	/* Named env value already exists? */
	for (env_p = env_h->env_list; *env_p != NULL; env_p++) {
		if ((*env_p)[name_len] == '=' &&
		    strn_eq(*env_p, name, name_len))
		{
			break;
		}
	}

	if (!*env_p) {
		/* Not exist. Adding a new env entry */
		char *env_new;

		if (env_h->env_size == env_h->env_num + 1) {
			/* Enlarge env_h->env_list */
			size_t env_size_new = env_h->env_size +
				ENV_SIZE_CHUNK;
			char **env_list_new = talloc_realloc(
				env_h, env_h->env_list, char *, env_size_new);
			if (!env_list_new) {
				DEBUG(0,("TALLOC_REALLOC_ARRAY failed\n"));
				return -1;
			}
			env_h->env_list = env_list_new;
			env_h->env_size = env_size_new;
		}

		env_new = talloc_asprintf(env_h, "%s=%s", name, value);
		if (!env_new) {
			DEBUG(0,("talloc_asprintf failed\n"));
			return -1;
		}
		*env_p = env_new;
		env_h->env_num++;
		env_h->env_list[env_h->env_num] = NULL;

		return 0;
	}

	if (strlen(*env_p) < env_len) {
		/* Exist, but buffer is too short */
		char *env_new = talloc_asprintf(env_h, "%s=%s", name, value);
		if (!env_new) {
			DEBUG(0,("talloc_asprintf failed\n"));
			return -1;
		}
		TALLOC_FREE(*env_p);
		*env_p = env_new;

		return 0;
	}

	/* Exist and buffer is enough to overwrite */
	snprintf(*env_p, env_len + 1, "%s=%s", name, value);

	return 0;
}
