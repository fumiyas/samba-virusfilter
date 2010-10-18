/*
   Samba Anti-Virus VFS modules
   Copyright (C) 2010 SATOH Fumiyasu @ OSS Technology, Inc.

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

#ifndef _SAV_UTILS_H
#define _SAV_UTILS_H

#include "sav-common.h"

#define str_eq(s1, s2)		((strcmp((s1), (s2)) == 0) ? true : false)
#define strn_eq(s1, s2, n)	((strncmp((s1), (s2), (n)) == 0) ? true : false)

#define SAV_IO_BUFFER_SIZE	(PATH_MAX + 1024)

typedef struct sav_io_handle {
	int		socket;
	int		eol;			/* end-of-line character */
	int		connect_timeout;	/* msec */
	int		timeout;		/* msec */
	char		w_buffer[SAV_IO_BUFFER_SIZE+1];
	ssize_t		w_size;
	char		*r_buffer;
	char		r_buffer_real[SAV_IO_BUFFER_SIZE+1];
	ssize_t		r_size;
	char		*r_rest_buffer;
	ssize_t		r_rest_size;
} sav_io_handle;

typedef struct sav_cache_entry {
	struct sav_cache_entry *prev, *next;
	time_t time;
	char *fname;
	int fname_len;
	sav_result result;
	const char *report;
} sav_cache_entry;

typedef struct {
	sav_cache_entry *list, *end;
	int entry_num;
	int entry_limit;
	time_t time_limit;
} sav_cache_handle;

typedef struct {
	char		**env_list;
	size_t		env_size;
	size_t		env_num;
} sav_env_struct;

/* ====================================================================== */

char *sav_string_sub(TALLOC_CTX *mem_ctx, connection_struct *conn, const char *str);

/* Line-based socket I/O */
sav_io_handle *sav_io_new(TALLOC_CTX *mem_ctx, int connect_timeout, int timeout);
int sav_io_set_eol(sav_io_handle *io_h, int eol);
sav_result sav_io_connect_path(sav_io_handle *io_h, const char *path);
sav_result sav_io_disconnect(sav_io_handle *io_h);
sav_result sav_io_write(sav_io_handle *io_h);
sav_result sav_io_read(sav_io_handle *io_h);
sav_result sav_io_writeread(sav_io_handle *io_h, const char *fmt, ...);

/* Scan result cache */
#define sav_cache_entry_new(cache_h) TALLOC_ZERO_P(cache_h, sav_cache_entry)
sav_cache_handle *sav_cache_new(TALLOC_CTX *ctx, int entry_limit, time_t time_limit);
sav_cache_entry *sav_cache_get(sav_cache_handle *cache_h, const char *fname, int fname_len);
void sav_cache_add(sav_cache_handle *cache_h, sav_cache_entry *cache_e);

/* Environment variable handling for execle(2) */
sav_env_struct *sav_env_new(TALLOC_CTX *ctx);
char * const *sav_env_list(sav_env_struct *env_h);
int sav_env_set(sav_env_struct *env_h, const char *name, const char *value);

/* Shell scripting */
int sav_shell_set_conn_env(sav_env_struct *env_h, connection_struct *conn);
int sav_shell_run(
	const char *cmd,
	uid_t uid,
	gid_t gid,
	sav_env_struct *env_h,
	connection_struct *conn,
	bool sanitize);

#endif /* _SAV_UTILS_H */

