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

#ifndef _SAV_VFS_H
#define _SAV_VFS_H

#include "sav-common.h"
#include "sav-utils.h"

#define SAV_MODULE_NAME "sav-" SAV_MODULE_ENGINE

/* Default configuration values
 * ====================================================================== */

#define SAV_DEFAULT_SCAN_ON_OPEN		true
#define SAV_DEFAULT_SCAN_ON_CLOSE		false
#define SAV_DEFAULT_MAX_FILE_SIZE		500000000L /* 500MB */
#define SAV_DEFAULT_MIN_FILE_SIZE		10

#define SAV_DEFAULT_CACHE_ENTRY_LIMIT		100
#define SAV_DEFAULT_CACHE_TIME_LIMIT		10

#define SAV_DEFAULT_INFECTED_FILE_ACTION	SAV_ACTION_DO_NOTHING
#define SAV_DEFAULT_INFECTED_FILE_COMMAND	NULL
#define SAV_DEFAULT_INFECTED_FILE_ERRNO_ON_OPEN	EACCES
#define SAV_DEFAULT_INFECTED_FILE_ERRNO_ON_CLOSE 0

#define SAV_DEFAULT_SCAN_ERROR_COMMAND		NULL
#define SAV_DEFAULT_SCAN_ERROR_ERRNO_ON_OPEN	EACCES
#define SAV_DEFAULT_SCAN_ERROR_ERRNO_ON_CLOSE	0
#define SAV_DEFAULT_BLOCK_ACCESS_ON_ERROR	false

#define SAV_DEFAULT_QUARANTINE_DIRECTORY	VARDIR "/sav/quarantine"
#define SAV_DEFAULT_QUARANTINE_PREFIX		"sav."

/* ====================================================================== */

int sav_debug_level = DBGC_VFS;

static const struct enum_list sav_actions[] = {
	{ SAV_ACTION_QUARANTINE,	"quarantine" },
	{ SAV_ACTION_DELETE,		"delete" },
	{ SAV_ACTION_DELETE,		"remove" },	/* alias for "delete" */
	{ SAV_ACTION_DELETE,		"unlink" },	/* alias for "delete" */
	{ SAV_ACTION_DO_NOTHING,	"nothing" },
	{ -1,				NULL}
};

typedef struct {
#ifdef SAV_DEFAULT_SCAN_LIMIT
	int				scan_count;
	int				scan_limit;
#endif
	/* Scan on file operations */
	bool				scan_on_open;
	bool				scan_on_close;
	/* Special scan options */
#ifdef SAV_DEFAULT_SCAN_ARCHIVE
        bool				scan_archive;
#endif
#ifdef SAV_DEFAULT_MAX_NESTED_SCAN_ARCHIVE
        int				max_nested_scan_archive;
#endif
#ifdef SAV_DEFAULT_SCAN_MIME
        bool				scan_mime;
#endif
	/* Size limit */
	ssize_t				max_file_size;
	ssize_t				min_file_size;
	/* Scan result cache */
	sav_cache_handle		*cache;
	int				cache_entry_limit;
	int				cache_time_limit;
	/* Infected file options */
	sav_action			infected_file_action;
	const char *			infected_file_command;
	int				infected_file_errno_on_open;
	int				infected_file_errno_on_close;
	/* Scan error options */
	const char *			scan_error_command;
	int				scan_error_errno_on_open;
	int				scan_error_errno_on_close;
	bool				block_access_on_error;
	/* Quarantine infected files */
	const char *			quarantine_dir;
	const char *			quarantine_prefix;
	/* Network options */
#ifdef SAV_DEFAULT_SOCKET_PATH
        const char *			socket_path;
	sav_io_handle			*io_h;
#endif
	/* Module specific configuration options */
#ifdef SAV_MODULE_CONFIG_MEMBERS
	SAV_MODULE_CONFIG_MEMBERS
#endif
} sav_handle;

/* ====================================================================== */

#ifdef sav_module_connect
static int sav_module_connect(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *svc,
	const char *user);
#endif

#ifdef sav_module_disconnect
static int sav_module_disconnect(vfs_handle_struct *vfs_h);
#endif

#ifdef sav_module_destruct_config
static int sav_module_destruct_config(sav_handle *sav_h);
#endif

#ifdef sav_module_scan_init
static sav_result sav_module_scan_init(sav_handle *sav_h);
#endif

#ifdef sav_module_scan_end
static void sav_module_scan_end(sav_handle *sav_h);
#endif

static sav_result sav_module_scan(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *filepath,
	const char **reportp);

/* ====================================================================== */

static int sav_destruct_config(sav_handle *sav_h)
{
#ifdef sav_module_destruct_config
	/* FIXME: Check return code */
	sav_module_destruct_config(sav_h);
#endif

	TALLOC_FREE(sav_h);

	return 0;
}

static int sav_vfs_connect(
	vfs_handle_struct *vfs_h,
	const char *svc,
	const char *user)
{
	int snum = SNUM(vfs_h->conn);
	sav_handle *sav_h;
#ifdef SAV_DEFAULT_SOCKET_PATH
	int connect_timeout, timeout;
#endif


	sav_h = TALLOC_ZERO_P(vfs_h, sav_handle);
	if (!sav_h) {
		DEBUG(0, ("TALLOC_ZERO_P failed\n"));
		return -1;
	}

	talloc_set_destructor(sav_h, sav_destruct_config);

	SMB_VFS_HANDLE_SET_DATA(vfs_h,
		sav_h,
		NULL,
		sav_handle *,
		return -1);

#ifdef SAV_DEFAULT_SCAN_LIMIT
        sav_h->scan_limit = lp_parm_int(
		snum, SAV_MODULE_NAME,
		"scan limit",
		SAV_DEFAULT_SCAN_LIMIT);
#endif

        sav_h->scan_on_open = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"scan on open",
		SAV_DEFAULT_SCAN_ON_OPEN);
        sav_h->scan_on_close = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"scan on close",
		SAV_DEFAULT_SCAN_ON_CLOSE);
#ifdef SAV_DEFAULT_MAX_NESTED_SCAN_ARCHIVE
        sav_h->max_nested_scan_archive = lp_parm_int(
		snum, SAV_MODULE_NAME,
		"max nested scan archive",
		SAV_DEFAULT_MAX_NESTED_SCAN_ARCHIVE);
#endif
#ifdef SAV_DEFAULT_SCAN_ARCHIVE
        sav_h->scan_archive = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"scan archive",
		SAV_DEFAULT_SCAN_ARCHIVE);
#endif
#ifdef SAV_DEFAULT_MIME_SCAN
        sav_h->scan_mime = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"scan mime",
		SAV_DEFAULT_SCAN_MIME);
#endif

        sav_h->max_file_size = (ssize_t)lp_parm_ulong(
		snum, SAV_MODULE_NAME,
		"max file size",
		SAV_DEFAULT_MAX_FILE_SIZE);
        sav_h->min_file_size = (ssize_t)lp_parm_ulong(
		snum, SAV_MODULE_NAME,
		"min file size",
		SAV_DEFAULT_MIN_FILE_SIZE);

        sav_h->cache_entry_limit = lp_parm_int(
		snum, SAV_MODULE_NAME,
		"cache entry limit",
		SAV_DEFAULT_CACHE_ENTRY_LIMIT);
        sav_h->cache_time_limit = lp_parm_int(
		snum, SAV_MODULE_NAME,
		"cache time limit",
		SAV_DEFAULT_CACHE_TIME_LIMIT);

        sav_h->infected_file_action = lp_parm_enum(
		snum, SAV_MODULE_NAME,
		"infected file action", sav_actions,
		SAV_DEFAULT_INFECTED_FILE_ACTION);
        sav_h->infected_file_command = lp_parm_const_string(
		snum, SAV_MODULE_NAME,
		"infected file command",
		SAV_DEFAULT_INFECTED_FILE_COMMAND);
        sav_h->scan_error_command = lp_parm_const_string(
		snum, SAV_MODULE_NAME,
		"scan error command",
		SAV_DEFAULT_SCAN_ERROR_COMMAND);
        sav_h->block_access_on_error = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"block access on error",
		SAV_DEFAULT_BLOCK_ACCESS_ON_ERROR);

        sav_h->quarantine_dir = lp_parm_const_string(
		snum, SAV_MODULE_NAME,
		"quarantine directory",
		SAV_DEFAULT_QUARANTINE_DIRECTORY);
        sav_h->quarantine_prefix = lp_parm_const_string(
		snum, SAV_MODULE_NAME,
		"quarantine prefix",
		SAV_DEFAULT_QUARANTINE_PREFIX);

	/* FIXME: Support lp_parm_enum(...) */
        sav_h->infected_file_errno_on_open =SAV_DEFAULT_INFECTED_FILE_ERRNO_ON_OPEN;
        sav_h->infected_file_errno_on_close = SAV_DEFAULT_INFECTED_FILE_ERRNO_ON_CLOSE;
        sav_h->scan_error_errno_on_open = SAV_DEFAULT_SCAN_ERROR_ERRNO_ON_OPEN;
        sav_h->scan_error_errno_on_close = SAV_DEFAULT_SCAN_ERROR_ERRNO_ON_CLOSE;

#ifdef SAV_DEFAULT_SOCKET_PATH
        sav_h->socket_path = lp_parm_const_string(
		snum, SAV_MODULE_NAME,
		"socket path",
		SAV_DEFAULT_SOCKET_PATH);
        connect_timeout = lp_parm_int(
		snum, SAV_MODULE_NAME,
		"connect timeout",
		SAV_DEFAULT_CONNECT_TIMEOUT);
        timeout = lp_parm_int(
		snum, SAV_MODULE_NAME,
		"timeout",
		SAV_DEFAULT_TIMEOUT);

	sav_h->io_h = sav_io_new(sav_h, connect_timeout, timeout);
	if (!sav_h->io_h) {
		DEBUG(0,("sav_io_new failed"));
		return -1;
	}
#endif

	if (sav_h->cache_entry_limit >= 0) {
		sav_h->cache = sav_cache_new(sav_h,
			sav_h->cache_entry_limit, sav_h->cache_time_limit);
		if (!sav_h->cache) {
			DEBUG(0,("Initializing cache failed: Cache disabled"));
		}
	}

#ifdef sav_module_connect
	if (sav_module_connect(vfs_h, sav_h, svc, user) == -1) {
		return -1;
	}
#endif

	return SMB_VFS_NEXT_CONNECT(vfs_h, svc, user);
}

static void sav_vfs_disconnect(vfs_handle_struct *vfs_h)
{
	sav_handle *sav_h;

#ifdef sav_module_disconnect
	sav_module_disconnect(vfs_h);
#endif

#ifdef SAV_DEFAULT_SOCKET_PATH
	SMB_VFS_HANDLE_GET_DATA(vfs_h, sav_h,
				sav_handle,
				return);

	sav_io_disconnect(sav_h->io_h);
#endif

	SMB_VFS_NEXT_DISCONNECT(vfs_h);
}

static sav_action sav_do_infected_file_action(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *filepath,
	const char **filepath_newp)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	connection_struct *conn = vfs_h->conn;
	*filepath_newp = NULL;
	char *q_dir;
	char *q_prefix;
	char *q_filepath;
	int q_fd;

	switch (sav_h->infected_file_action) {
	case SAV_ACTION_QUARANTINE:
		/* FIXME: Do SMB_VFS_NEXT_MKDIR(sav_h->quarantine_dir) hierarchy */
		q_dir = sav_string_sub(mem_ctx, conn, sav_h->quarantine_dir);
		q_prefix = sav_string_sub(mem_ctx, conn, sav_h->quarantine_prefix);
		if (!q_dir || !q_prefix) {
			DEBUG(0,("Quarantine failed: %s: Cannot allocate memory", filepath));
			return SAV_ACTION_DO_NOTHING;
		}
		q_filepath = talloc_asprintf(talloc_tos(), "%s/%sXXXXXX", q_dir, q_prefix);
		TALLOC_FREE(q_dir);
		TALLOC_FREE(q_prefix);
		if (!q_filepath) {
			DEBUG(0,("Quarantine failed: %s: Cannot allocate memory", filepath));
			return SAV_ACTION_DO_NOTHING;
		}

		become_root();

		q_fd = smb_mkstemp(q_filepath);
		if (q_fd == -1) {
			unbecome_root();
			DEBUG(0,("Quarantine failed: %s: Cannot open destination: %s: %s",
				filepath, q_filepath, strerror(errno)));
			return SAV_ACTION_DO_NOTHING;
		}
		close(q_fd);

		if (SMB_VFS_NEXT_RENAME(vfs_h, filepath, q_filepath) == -1) {
#if SAMBA_VERSION_NUMBER >= 30600
#  error FIXME: Do copy_reg() instead if errno == EXDEV for Samba 3.6+
#endif
			unbecome_root();
			DEBUG(0,("Quarantine failed: %s: Rename failed: %s",
				filepath, strerror(errno)));
			return SAV_ACTION_DO_NOTHING;
		}
		unbecome_root();

		*filepath_newp = q_filepath;

		return SAV_ACTION_QUARANTINE;

	case SAV_ACTION_DELETE:
		become_root();
		if (SMB_VFS_NEXT_UNLINK(vfs_h, filepath) == -1) {
			unbecome_root();
			DEBUG(0,("Delete failed: %s: Unlink failed: %s",
				filepath, strerror(errno)));
			return SAV_ACTION_DO_NOTHING;
		}
		unbecome_root();
		return SAV_ACTION_DELETE;

	case SAV_ACTION_DO_NOTHING:
	default:
		return SAV_ACTION_DO_NOTHING;
	}
}

static sav_action sav_treat_infected_file(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *filepath,
	const char *report,
	bool is_cache)
{
	connection_struct *conn = vfs_h->conn;
	TALLOC_CTX *mem_ctx = talloc_tos();
	int i;
	sav_action action;
	const char *action_name = "UNKNOWN";
	const char *filepath_q = NULL;
	sav_env_struct *env_h = NULL;
	char *command = NULL;
	int command_result;

	action = sav_do_infected_file_action(vfs_h, sav_h, filepath, &filepath_q);
	for (i=0; sav_actions[i].name; i++) {
		if (sav_actions[i].value == action) {
			action_name = sav_actions[i].name;
			break;
		}
	}
	DEBUG(1,("Infected file action: %s: %s\n", filepath, action_name));

	if (!sav_h->infected_file_command) {
		return action;
	}

	env_h = sav_env_new(mem_ctx);
	if (!env_h) {
		DEBUG(0,("sav_env_new failed\n"));
		goto done;
	}
	if (sav_env_set(env_h, "SAV_VERSION", SAV_VERSION) == -1) {
		goto done;
	}
	if (sav_env_set(env_h, "SAV_MODULE_NAME", SAV_MODULE_NAME) == -1) {
		goto done;
	}
#ifdef SAV_MODULE_VERSION
	if (sav_env_set(env_h, "SAV_MODULE_VERSION", SAV_MODULE_VERSION) == -1) {
		goto done;
	}
#endif
	if (sav_env_set(env_h, "SAV_INFECTED_FILE_PATH", filepath) == -1) {
		goto done;
	}
	if (report && sav_env_set(env_h, "SAV_INFECTED_FILE_REPORT", report) == -1) {
		goto done;
	}
	if (sav_env_set(env_h, "SAV_INFECTED_FILE_ACTION", action_name) == -1) {
		goto done;
	}
	if (filepath_q && sav_env_set(env_h, "SAV_QUARANTINED_FILE_PATH", filepath_q) == -1) {
		goto done;
	}
	if (is_cache && sav_env_set(env_h, "SAV_RESULT_IS_CACHE", "yes") == -1) {
		goto done;
	}

	command = sav_string_sub(mem_ctx, conn, sav_h->infected_file_command);
	if (!command) {
		DEBUG(0,("sav_string_sub failed\n"));
		goto done;
	}

	DEBUG(3,("Infected file command: %s: %s\n", filepath, command));

	command_result = sav_shell_run(command, 0, 0, env_h, vfs_h->conn, true);
	if (command_result != 0) {
		DEBUG(0,("Infected file command failed: %d\n", command_result));
	}

done:
	TALLOC_FREE(env_h);
	TALLOC_FREE(command);

	return action;
}

static void sav_treat_scan_error(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *filepath,
	const char *report,
	bool is_cache)
{
	connection_struct *conn = vfs_h->conn;
	TALLOC_CTX *mem_ctx = talloc_tos();
	sav_env_struct *env_h = NULL;
	char *command = NULL;
	int command_result;

	if (!sav_h->scan_error_command) {
		return;
	}

	env_h = sav_env_new(mem_ctx);
	if (!env_h) {
		DEBUG(0,("sav_env_new failed\n"));
		goto done;
	}
	if (sav_env_set(env_h, "SAV_SCAN_ERROR_FILE_PATH", filepath) == -1) {
		goto done;
	}
	if (report && sav_env_set(env_h, "SAV_SCAN_ERROR_REPORT", report) == -1) {
		goto done;
	}
	if (is_cache && sav_env_set(env_h, "SAV_RESULT_IS_CACHE", "1") == -1) {
		goto done;
	}

	command = sav_string_sub(mem_ctx, conn, sav_h->scan_error_command);
	if (!command) {
		DEBUG(0,("sav_string_sub failed\n"));
		goto done;
	}

	DEBUG(3,("Scan error command: %s: %s\n", filepath, command));

	command_result = sav_shell_run(command, 0, 0, env_h, vfs_h->conn, true);
	if (command_result != 0) {
		DEBUG(0,("Scan error command failed: %d\n", command_result));
	}

done:
	TALLOC_FREE(env_h);
	TALLOC_FREE(command);
}

static sav_result sav_scan(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *fname)
{
	sav_result scan_result;
	const char *scan_report = NULL;
	char *filepath;
	sav_cache_entry *scan_cache_e = NULL;
	bool is_cache = false;
	sav_action file_action;
	bool add_scan_cache;

	filepath = talloc_asprintf(talloc_tos(), "%s/%s", vfs_h->conn->connectpath, fname);
	if (!filepath) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		return SAV_RESULT_ERROR;
	}

	if (sav_h->cache) {
		DEBUG(10, ("Searching cache entry: fname: %s\n", fname));
		scan_cache_e = sav_cache_get(sav_h->cache, fname, -1);
		if (scan_cache_e) {
			DEBUG(10, ("Cache entry found: cached result: %d\n", scan_cache_e->result));
			is_cache = true;
			scan_result = scan_cache_e->result;
			scan_report = scan_cache_e->report;
			goto sav_scan_result_eval;
		}
		DEBUG(10, ("Cache entry not found\n"));
	} else {
		DEBUG(10, ("Cache disabled\n"));
	}

#ifdef sav_module_scan_init
	if (sav_module_scan_init(sav_h) != SAV_RESULT_OK) {
		scan_result = SAV_RESULT_ERROR;
		scan_report = "Initializing scanner failed";
		goto sav_scan_result_eval;
	}
#endif

	scan_result = sav_module_scan(vfs_h, sav_h, filepath, &scan_report);

#ifdef sav_module_scan_end
#ifdef SAV_DEFAULT_SCAN_LIMIT
	if (sav_h->scan_limit > 0) {
		sav_h->scan_count++;
		if (sav_h->scan_count >= sav_h->scan_limit) {
			sav_module_scan_end(sav_h);
			sav_h->scan_count = 0;
		}
	}
#else
	sav_module_scan_end(sav_h);
#endif
#endif

sav_scan_result_eval:

	file_action = SAV_ACTION_DO_NOTHING;
	add_scan_cache = true;

	switch (scan_result) {
	case SAV_RESULT_CLEAN:
		DEBUG(5, ("Scan result: Clean: %s\n", filepath));
		break;
	case SAV_RESULT_INFECTED:
		DEBUG(0, ("Scan result: Infected: %s: %s\n", filepath, scan_report));
		file_action = sav_treat_infected_file(vfs_h, sav_h, filepath, scan_report, is_cache);
		if (file_action != SAV_ACTION_DO_NOTHING) {
			add_scan_cache = false;
		}
		break;
	case SAV_RESULT_ERROR:
		DEBUG(0, ("Scan result: Error: %s: %s\n", filepath, scan_report));
		sav_treat_scan_error(vfs_h, sav_h, filepath, scan_report, is_cache);
		break;
	default:
		DEBUG(0, ("Scan result: Unknown result code %d: %s: %s\n",
			scan_result, filepath, scan_report));
		sav_treat_scan_error(vfs_h, sav_h, filepath, scan_report, is_cache);
		break;
	}

	if (sav_h->cache && !is_cache && add_scan_cache) {
		DEBUG(10, ("Adding new cache entry: %s, %d\n", fname, scan_result));
		scan_cache_e = sav_cache_entry_new(sav_h->cache);
		if (!scan_cache_e) {
			DEBUG(0,("Cannot create cache entry: sav_cache_entry_new failed"));
			goto sav_scan_return;
		}
		scan_cache_e->fname = talloc_strdup(scan_cache_e, fname);
		if (!scan_cache_e->fname) {
			DEBUG(0,("Cannot create cache entry: talloc_strdup failed"));
			TALLOC_FREE(scan_cache_e);
			goto sav_scan_return;
		}
		scan_cache_e->result = scan_result;
		scan_cache_e->report = scan_report ? talloc_strdup(scan_cache_e, scan_report) : NULL;
		if (!scan_cache_e->report) {
			DEBUG(0,("Cannot create cache entry: talloc_strdup failed"));
			TALLOC_FREE(scan_cache_e);
			goto sav_scan_return;
		}
		sav_cache_add(sav_h->cache, scan_cache_e);
	}

sav_scan_return:

	return scan_result;
}

static int sav_vfs_open(
	vfs_handle_struct *vfs_h,
	const char *fname, files_struct *fsp,
	int flags, mode_t mode)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	sav_handle *sav_h;
	SMB_STRUCT_STAT stat_buf;
	sav_result scan_result;
	int scan_errno = 0;

	SMB_VFS_HANDLE_GET_DATA(vfs_h, sav_h,
				sav_handle,
				return -1);

        if (!sav_h->scan_on_open) {
                DEBUG(5, ("Not scanned: scan on open is disabled: %s/%s\n",
			vfs_h->conn->connectpath, fname));
		goto sav_vfs_open_next;
        }

	if (flags & O_TRUNC) {
                DEBUG(5, ("Not scanned: Open flags have O_TRUNC: %s/%s\n",
			vfs_h->conn->connectpath, fname));
		goto sav_vfs_open_next;
	}

	if (SMB_VFS_NEXT_STAT(vfs_h, fname, &stat_buf) != 0) {
		/* FIXME: Return immediately if !(flags & O_CREAT) && errno != ENOENT? */
		goto sav_vfs_open_next;
	}
	if (!S_ISREG(stat_buf.st_mode)) {
                DEBUG(5, ("Not scanned: Directory or special file: %s/%s\n",
			vfs_h->conn->connectpath, fname));
		goto sav_vfs_open_next;
	}
	if (sav_h->max_file_size > 0 && stat_buf.st_size > sav_h->max_file_size) {
                DEBUG(5, ("Not scanned: file size > max file size: %s/%s\n",
			vfs_h->conn->connectpath, fname));
		goto sav_vfs_open_next;
	}
	if (sav_h->min_file_size > 0 && stat_buf.st_size < sav_h->min_file_size) {
                DEBUG(5, ("Not scanned: file size < min file size: %s/%s\n",
			vfs_h->conn->connectpath, fname));
		goto sav_vfs_open_next;
	}

	scan_result = sav_scan(vfs_h, sav_h, fname);

	switch (scan_result) {
	case SAV_RESULT_CLEAN:
		break;
	case SAV_RESULT_INFECTED:
		scan_errno = sav_h->infected_file_errno_on_open;
		goto sav_vfs_open_fail;
	case SAV_RESULT_ERROR:
		if (sav_h->block_access_on_error) {
			DEBUG(5, ("Block access\n"));
			scan_errno = sav_h->scan_error_errno_on_open;
			goto sav_vfs_open_fail;
		}
		break;
	default:
		scan_errno = sav_h->scan_error_errno_on_open;
		goto sav_vfs_open_fail;
	}

sav_vfs_open_next:
	TALLOC_FREE(mem_ctx);
	return SMB_VFS_NEXT_OPEN(vfs_h, fname, fsp, flags, mode);

sav_vfs_open_fail:
	TALLOC_FREE(mem_ctx);
	errno = (scan_errno != 0) ? scan_errno : EACCES;
	return -1;
}

static int sav_vfs_close(
	vfs_handle_struct *vfs_h,
	files_struct *fsp,
	int fd)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	connection_struct *conn = vfs_h->conn;
	sav_handle *sav_h;
	int close_result, close_errno;
	sav_result scan_result;
	int scan_errno = 0;

	SMB_VFS_HANDLE_GET_DATA(vfs_h, sav_h,
				sav_handle,
				return -1);

	/* FIXME: Must close after scan? */
	close_result = SMB_VFS_NEXT_CLOSE(vfs_h, fsp);
	close_errno = errno;
	/* FIXME: Return immediately if errno_result == -1, and close_errno == EBADF or ...? */

	if (fsp->is_directory) {
                DEBUG(5, ("Not scanned: Directory: %s/%s\n",
			conn->connectpath, fsp->fsp_name));
		return close_result;
	}

	if (!sav_h->scan_on_close) {
                DEBUG(5, ("Not scanned: scan on close is disabled: %s/%s\n",
			conn->connectpath, fsp->fsp_name));
		return close_result;
	}

	if (!fsp->modified) {
		DEBUG(3, ("Not scanned: File not modified: %s/%s\n",
			conn->connectpath, fsp->fsp_name));

		return close_result;
	}

	scan_result = sav_scan(vfs_h, sav_h, fsp->fsp_name);

	switch (scan_result) {
	case SAV_RESULT_CLEAN:
		break;
	case SAV_RESULT_INFECTED:
		scan_errno = sav_h->infected_file_errno_on_close;
		goto sav_vfs_close_fail;
	case SAV_RESULT_ERROR:
		if (sav_h->block_access_on_error) {
			DEBUG(5, ("Block access\n"));
			scan_errno = sav_h->scan_error_errno_on_close;
			goto sav_vfs_close_fail;
		}
		break;
	default:
		scan_errno = sav_h->scan_error_errno_on_close;
		goto sav_vfs_close_fail;
	}

	TALLOC_FREE(mem_ctx);
	errno = close_errno;

	return close_result;

sav_vfs_close_fail:

	TALLOC_FREE(mem_ctx);
	errno = (scan_errno != 0) ? scan_errno : close_errno;

	return close_result;
}

/* VFS operations */
static vfs_op_tuple sav_ops[] = {
	/* Disk operations */
	{
		SMB_VFS_OP(sav_vfs_connect),
		SMB_VFS_OP_CONNECT,
		SMB_VFS_LAYER_TRANSPARENT
	},
	{
		SMB_VFS_OP(sav_vfs_disconnect),
		SMB_VFS_OP_DISCONNECT,
		SMB_VFS_LAYER_TRANSPARENT
	},

	/* File operations */
	{
		SMB_VFS_OP(sav_vfs_open),
		SMB_VFS_OP_OPEN,
		SMB_VFS_LAYER_TRANSPARENT
	},
	{
		SMB_VFS_OP(sav_vfs_close),
		SMB_VFS_OP_CLOSE,
		SMB_VFS_LAYER_TRANSPARENT
	},

	/* Finish VFS operations definition */
	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS init_samba_module(void)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				SAV_MODULE_NAME, sav_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	sav_debug_level = debug_add_class(SAV_MODULE_NAME);
	if (sav_debug_level == -1) {
		sav_debug_level = DBGC_VFS;
		DEBUG(0, ("Couldn't register custom debugging class!\n"));
	} else {
		DEBUG(10, ("Debug class number of '%s': %d\n",
			SAV_MODULE_NAME, sav_debug_level));
	}

	DEBUG(5,("%s registered\n", SAV_MODULE_NAME));

	return ret;
}

#endif /* _SAV_VFS_H */

