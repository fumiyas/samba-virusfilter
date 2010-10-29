/*
   Samba-VirusFilter VFS modules
   Sophos Anti-Virus svfdid (Sophie protocol) support
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

#define SVF_MODULE_ENGINE "sophos"

/* Default values for standard "extra" configuration variables */
#ifdef SOPHOS_DEFAULT_SOCKET_PATH
#  define SVF_DEFAULT_SOCKET_PATH		SOPHOS_DEFAULT_SOCKET_PATH
#else
#  define SVF_DEFAULT_SOCKET_PATH		"/var/tmp/svfid/sophie.sock"
#endif
#define SVF_DEFAULT_CONNECT_TIMEOUT		30000 /* msec */
#define SVF_DEFAULT_TIMEOUT			60000 /* msec */
/* Default values for module-specific configuration variables */
/* None */

#define svf_module_scan_init			svf_sophos_scan_init
#define svf_module_scan_end			svf_sophos_scan_end
#define svf_module_scan				svf_sophos_scan

#include "svf-vfs.h"

/* ====================================================================== */

#include "svf-utils.h"

/* ====================================================================== */

static svf_result svf_sophos_scan_init(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result;

	DEBUG(0,("Connecting to svfdid (sophie) socket: %s\n", svf_h->socket_path));

	become_root();
	result = svf_io_connect_path(io_h, svf_h->socket_path);
	unbecome_root();

	if (result != SVF_RESULT_OK) {
		DEBUG(0,("Connecting to svfdid (sophie) socket failed: %s: %s\n",
			svf_h->socket_path, strerror(errno)));
		return SVF_RESULT_ERROR;
	}

	return SVF_RESULT_OK;
}

static void svf_sophos_scan_end(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;

	svf_io_disconnect(io_h);
}

static svf_result svf_sophos_scan(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const char *filepath,
	const char **reportp)
{
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result = SVF_RESULT_CLEAN;
	const char *report = NULL;
	char *reply;
	char *colon;

	if (svf_io_writefl_readl(io_h, "%s", filepath) != SVF_RESULT_OK) {
		DEBUG(0,("Scan failed: %s\n", strerror(errno)));
		result = SVF_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scan failed: %s\n", strerror(errno));
		goto svf_sophos_scan_return;
	}

	colon = strchr(io_h->r_buffer, ':');
	if (colon) {
		*colon = '\0';
		if (*(colon+1) != '\0') {
			reply = colon + 1;
		}
	}

	if (str_eq(io_h->r_buffer, "0") ) {
		/* 0 */
		result = SVF_RESULT_CLEAN;
		report = "Clean";
	} else if (str_eq(io_h->r_buffer, "1")) {
		/* 1:<REPORT> */
		result = SVF_RESULT_INFECTED;
		report = talloc_strdup(talloc_tos(), reply);
	} else if (str_eq(io_h->r_buffer, "-1")) {
		/* -1:<REPORT> */
		result = SVF_RESULT_ERROR;
		report = talloc_strdup(talloc_tos(), reply);
	} else {
		result = SVF_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Invalid reply from svfdid (sophie): %s\t", io_h->r_buffer);
		if (!report) {
			DEBUG(0,("talloc_asprintf failed\n"));
		}
	}

svf_sophos_scan_return:

	*reportp = report;

	return result;
}

