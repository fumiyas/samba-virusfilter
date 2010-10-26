/*
   Samba-VirusFilter VFS modules
   ClamAV clamd support
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
        svf_io_set_eol(svf_h->io_h, '\0');

	return 0;
}

static svf_result svf_clamav_scan_init(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result;

	DEBUG(0,("Connecting to clamd socket: %s\n", svf_h->socket_path));

	become_root();
	result = svf_io_connect_path(io_h, svf_h->socket_path);
	unbecome_root();

	if (result != SVF_RESULT_OK) {
		DEBUG(0,("Connecting to clamd socket failed: %s: %s\n",
			svf_h->socket_path, strerror(errno)));
		return SVF_RESULT_ERROR;
	}

	return SVF_RESULT_OK;
}

static void svf_clamav_scan_end(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;

	svf_io_disconnect(io_h);
}

static svf_result svf_clamav_scan(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const char *filepath,
	const char **reportp)
{
	svf_io_handle *io_h = svf_h->io_h;
	size_t filepath_len = strlen(filepath);
	svf_result result = SVF_RESULT_CLEAN;
	const char *report = NULL;
	char *reply_status;

	if (svf_io_writeread(io_h, "zSCAN %s", filepath) != SVF_RESULT_OK) {
		DEBUG(0,("zSCAN failed: %s\n", strerror(errno)));
		result = SVF_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"zSCAN failed: %s\n", strerror(errno));
		goto svf_clamav_scan_return;
	}

	if (io_h->r_buffer[filepath_len] != ':' || io_h->r_buffer[filepath_len+1] != ' ') {
		DEBUG(0,("Invalid reply from clamd: %s\n", io_h->r_buffer));
		result = SVF_RESULT_ERROR;
		goto svf_clamav_scan_return;
	}
	report = io_h->r_buffer + filepath_len + 2;

	reply_status = strrchr(io_h->r_buffer, ' ');
	if (!reply_status) {
		DEBUG(0,("Invalid reply from clamd: %s\n", io_h->r_buffer));
		result = SVF_RESULT_ERROR;
		goto svf_clamav_scan_return;
	}
	reply_status[0] = '\0';
	reply_status++;

	if (str_eq(reply_status, "OK") ) {
		/* <FILEPATH>: OK */
		result = SVF_RESULT_CLEAN;
		report = "Clean";
	} else if (str_eq(reply_status, "FOUND")) {
		/* <FILEPATH>: <REPORT> FOUND */
		result = SVF_RESULT_INFECTED;
	} else if (str_eq(reply_status, "ERROR")) {
		/* <FILEPATH>: <REPORT> ERROR */
		result = SVF_RESULT_ERROR;
	} else {
		result = SVF_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Invalid reply from clamd: %s\t", reply_status);
		if (!report) {
			DEBUG(0,("talloc_asprintf failed\n"));
		}
	}

svf_clamav_scan_return:

	*reportp = report;

	return result;
}

