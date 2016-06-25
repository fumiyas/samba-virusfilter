/*
   Samba-VirusFilter VFS modules
   ClamAV clamd support
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

#define SVF_MODULE_ENGINE "clamav"

/* Default values for standard "extra" configuration variables */
#ifdef CLAMAV_DEFAULT_SOCKET_PATH
#  define SVF_DEFAULT_SOCKET_PATH		CLAMAV_DEFAULT_SOCKET_PATH
#else
#  define SVF_DEFAULT_SOCKET_PATH		"/var/run/clamav/clamd.ctl"
#endif
#define SVF_DEFAULT_CONNECT_TIMEOUT		30000 /* msec */
#define SVF_DEFAULT_TIMEOUT			60000 /* msec */
/* Default values for module-specific configuration variables */
/* None */

#define svf_module_connect			svf_clamav_connect
#define svf_module_scan_init			svf_clamav_scan_init
#define svf_module_scan_end			svf_clamav_scan_end
#define svf_module_scan				svf_clamav_scan

#include "svf-vfs.h"

/* ====================================================================== */

#include "svf-utils.h"

/* ====================================================================== */

static int svf_clamav_connect(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const char *svc,
	const char *user)
{
	/* To use clamd "zXXXX" commands */
        svf_io_set_writel_eol(svf_h->io_h, "\0", 1);
        svf_io_set_readl_eol(svf_h->io_h, "\0", 1);

	return 0;
}

static svf_result svf_clamav_scan_init(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result;

	DEBUG(7,("clamd: Connecting to socket: %s\n", svf_h->socket_path));

	become_root();
	result = svf_io_connect_path(io_h, svf_h->socket_path);
	unbecome_root();

	if (result != SVF_RESULT_OK) {
		DEBUG(0,("clamd: Connecting to socket failed: %s: %s\n",
			svf_h->socket_path, strerror(errno)));
		return SVF_RESULT_ERROR;
	}

	DEBUG(7,("clamd: Connected\n"));

	return SVF_RESULT_OK;
}

static void svf_clamav_scan_end(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;

	DEBUG(7,("clamd: Disconnecting\n"));

	svf_io_disconnect(io_h);
}

static svf_result svf_clamav_scan(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const struct smb_filename *smb_fname,
	const char **reportp)
{
	const char *connectpath = vfs_h->conn->connectpath;
	const char *fname = smb_fname->base_name;
	size_t filepath_len = strlen(connectpath) + 1 /* slash */ + strlen(fname);
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result = SVF_RESULT_CLEAN;
	char *report = NULL;
	char *reply;
	char *reply_token;

	DEBUG(7,("Scanning file: %s/%s\n", connectpath, fname));

	if (svf_io_writefl_readl(io_h, "zSCAN %s/%s",
	    connectpath, fname) != SVF_RESULT_OK) {
		DEBUG(0,("clamd: zSCAN: I/O error: %s\n", strerror(errno)));
		result = SVF_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scanner I/O error: %s\n", strerror(errno));
		goto svf_clamav_scan_return;
	}

	if (io_h->r_buffer[filepath_len] != ':' || io_h->r_buffer[filepath_len+1] != ' ') {
		DEBUG(0,("clamd: zSCAN: Invalid reply: %s\n", io_h->r_buffer));
		result = SVF_RESULT_ERROR;
		report = "Scanner communication error";
		goto svf_clamav_scan_return;
	}
	reply = io_h->r_buffer + filepath_len + 2;

	reply_token = strrchr(io_h->r_buffer, ' ');
	if (!reply_token) {
		DEBUG(0,("clamd: zSCAN: Invalid reply: %s\n", io_h->r_buffer));
		result = SVF_RESULT_ERROR;
		report = "Scanner communication error";
		goto svf_clamav_scan_return;
	}
	*reply_token = '\0';
	reply_token++;

	if (str_eq(reply_token, "OK") ) {
		/* <FILEPATH>: OK */
		result = SVF_RESULT_CLEAN;
		report = "Clean";
	} else if (str_eq(reply_token, "FOUND")) {
		/* <FILEPATH>: <REPORT> FOUND */
		result = SVF_RESULT_INFECTED;
		report = talloc_strdup(talloc_tos(), reply);
	} else if (str_eq(reply_token, "ERROR")) {
		/* <FILEPATH>: <REPORT> ERROR */
		DEBUG(0,("clamd: zSCAN: Error: %s\n", reply));
		result = SVF_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scanner error: %s\t", reply);
	} else {
		DEBUG(0,("clamd: zSCAN: Invalid reply: %s\n", reply_token));
		result = SVF_RESULT_ERROR;
		report = "Scanner communication error";
	}

svf_clamav_scan_return:
	*reportp = report;

	return result;
}

