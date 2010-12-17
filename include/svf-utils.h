/*
   Samba-VirusFilter VFS modules
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

#ifndef _SVF_UTILS_H
#define _SVF_UTILS_H

#include "svf-common.h"

#define str_eq(s1, s2)		((strcmp((s1), (s2)) == 0) ? true : false)
#define strn_eq(s1, s2, n)	((strncmp((s1), (s2), (n)) == 0) ? true : false)

#define SVF_IO_URL_MAX		(PATH_MAX * 3) /* "* 3" is for %-encoding */
#define SVF_IO_BUFFER_SIZE	(SVF_IO_URL_MAX + 128)
#define SVF_IO_EOL_SIZE		2
#define SVF_IO_IOV_MAX		16

typedef struct svf_io_handle {
	int		socket;
	int		connect_timeout;	/* msec */
	int		timeout;		/* msec */
	char		w_eol[SVF_IO_EOL_SIZE];	/* end-of-line character(s) */
	int		w_eol_size;
	char		r_eol[SVF_IO_EOL_SIZE];	/* end-of-line character(s) */
	int		r_eol_size;
	char		*r_buffer;
	char		r_buffer_real[SVF_IO_BUFFER_SIZE+1];
	ssize_t		r_size;
	char		*r_rest_buffer;
	ssize_t		r_rest_size;
} svf_io_handle;

typedef struct svf_cache_entry {
	struct svf_cache_entry *prev, *next;
	time_t time;
	char *fname;
	int fname_len;
	svf_result result;
	const char *report;
} svf_cache_entry;

typedef struct {
	svf_cache_entry *list, *end;
	int entry_num;
	int entry_limit;
	time_t time_limit;
} svf_cache_handle;

typedef struct {
	char		**env_list;
	size_t		env_size;
	size_t		env_num;
} svf_env_struct;

/* ====================================================================== */

char *svf_string_sub(TALLOC_CTX *mem_ctx, connection_struct *conn, const char *str);
int svf_url_quote(const char *src, char *dst, int dst_size);
#if SAMBA_VERSION_NUMBER >= 30600
int svf_vfs_next_move(
	vfs_handle_struct *handle,
	const struct smb_filename *smb_fname_src,
	const struct smb_filename *smb_fname_dst);
#else
#define svf_vfs_next_move SMB_VFS_NEXT_RENAME
#endif

/* Line-based socket I/O */
svf_io_handle *svf_io_new(TALLOC_CTX *mem_ctx, int connect_timeout, int timeout);
int svf_io_set_connect_timeout(svf_io_handle *io_h, int timeout);
int svf_io_set_timeout(svf_io_handle *io_h, int timeout);
void svf_io_set_writel_eol(svf_io_handle *io_h, const char *eol, int eol_size);
void svf_io_set_readl_eol(svf_io_handle *io_h, const char *eol, int eol_size);
svf_result svf_io_connect_path(svf_io_handle *io_h, const char *path);
svf_result svf_io_disconnect(svf_io_handle *io_h);
svf_result svf_io_write(svf_io_handle *io_h, const char *data, size_t data_size);
svf_result svf_io_writel(svf_io_handle *io_h, const char *data, size_t data_size);
svf_result svf_io_writefl(svf_io_handle *io_h, const char *data_fmt, ...);
svf_result svf_io_vwritefl(svf_io_handle *io_h, const char *data_fmt, va_list ap);
svf_result svf_io_writev(svf_io_handle *io_h, ...);
svf_result svf_io_writevl(svf_io_handle *io_h, ...);
svf_result svf_io_readl(svf_io_handle *io_h);
svf_result svf_io_writefl_readl(svf_io_handle *io_h, const char *fmt, ...);

/* Scan result cache */
#define svf_cache_entry_new(cache_h) TALLOC_ZERO_P(cache_h, svf_cache_entry)
svf_cache_handle *svf_cache_new(TALLOC_CTX *ctx, int entry_limit, time_t time_limit);
svf_cache_entry *svf_cache_get(svf_cache_handle *cache_h, const char *fname, int fname_len);
void svf_cache_add(svf_cache_handle *cache_h, svf_cache_entry *cache_e);

/* Environment variable handling for execle(2) */
svf_env_struct *svf_env_new(TALLOC_CTX *ctx);
char * const *svf_env_list(svf_env_struct *env_h);
int svf_env_set(svf_env_struct *env_h, const char *name, const char *value);

/* Shell scripting */
int svf_shell_set_conn_env(svf_env_struct *env_h, connection_struct *conn);
int svf_shell_run(
	const char *cmd,
	uid_t uid,
	gid_t gid,
	svf_env_struct *env_h,
	connection_struct *conn,
	bool sanitize);

#endif /* _SVF_UTILS_H */

