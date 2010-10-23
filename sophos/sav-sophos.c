/*
   Samba Anti-Virus VFS modules
   Sophos Anti-Virus savdid (Sophie protocol) support
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

#define SAV_MODULE_ENGINE "sophos"

/* Default values for standard "extra" configuration variables */
#ifdef SOPHOS_DEFAULT_SOCKET_PATH
#  define SAV_DEFAULT_SOCKET_PATH		SOPHOS_DEFAULT_SOCKET_PATH
#else
#  define SAV_DEFAULT_SOCKET_PATH		"/var/tmp/savid/sophie.sock"
#endif
#define SAV_DEFAULT_CONNECT_TIMEOUT		30000 /* msec */
#define SAV_DEFAULT_TIMEOUT			60000 /* msec */
/* Default values for module-specific configuration variables */
/* None */

#define sav_module_scan_init			sav_sophos_scan_init
#define sav_module_scan_end			sav_sophos_scan_end
#define sav_module_scan				sav_sophos_scan

#include "sav-vfs.h"

/* ====================================================================== */

#include "sav-utils.h"

/* ====================================================================== */

static sav_result sav_sophos_scan_init(sav_handle *sav_h)
{
	sav_io_handle *io_h = sav_h->io_h;
	sav_result result;

	DEBUG(0,("Connecting to savdid (sophie) socket: %s\n", sav_h->socket_path));

	become_root();
	result = sav_io_connect_path(io_h, sav_h->socket_path);
	unbecome_root();

	if (result != SAV_RESULT_OK) {
		DEBUG(0,("Connecting to savdid (sophie) socket failed: %s: %s\n",
			sav_h->socket_path, strerror(errno)));
		return SAV_RESULT_ERROR;
	}

	return SAV_RESULT_OK;
}

static void sav_sophos_scan_end(sav_handle *sav_h)
{
	sav_io_handle *io_h = sav_h->io_h;

	sav_io_disconnect(io_h);
}

static sav_result sav_sophos_scan(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *filepath,
	const char **reportp)
{
	sav_io_handle *io_h = sav_h->io_h;
	sav_result result = SAV_RESULT_CLEAN;
	const char *report = NULL;
	char *colon;

	if (sav_io_writeread(io_h, "%s", filepath) != SAV_RESULT_OK) {
		DEBUG(0,("Scan failed: %s\n", strerror(errno)));
		result = SAV_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scan failed: %s\n", strerror(errno));
		goto sav_sophos_scan_return;
	}

	colon = strchr(io_h->r_buffer, ':');
	if (colon) {
		*colon = '\0';
		if (*(colon+1) != '\0') {
			report = colon + 1;
		}
	}

	if (str_eq(io_h->r_buffer, "0") ) {
		/* 0 */
		result = SAV_RESULT_CLEAN;
		report = "Clean";
	} else if (str_eq(io_h->r_buffer, "1")) {
		/* 1:<REPORT> */
		result = SAV_RESULT_INFECTED;
	} else if (str_eq(io_h->r_buffer, "-1")) {
		/* -1:<REPORT> */
		result = SAV_RESULT_ERROR;
	} else {
		result = SAV_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Invalid reply from savdid (sophie): %s\t", io_h->r_buffer);
		if (!report) {
			DEBUG(0,("talloc_asprintf failed\n"));
		}
	}

sav_sophos_scan_return:

	*reportp = report;

	return result;
}

