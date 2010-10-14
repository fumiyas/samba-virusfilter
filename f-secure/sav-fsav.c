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

#define SAV_MODULE_ENGINE "fsav"

/* Default values for standard "extra" configuration variables */
#define SAV_DEFAULT_SCAN_LIMIT			0
#define SAV_DEFAULT_SOCKET_PATH			"/tmp/.fsav-0"
#define SAV_DEFAULT_CONNECT_TIMEOUT		30000 /* msec */
#define SAV_DEFAULT_TIMEOUT			60000 /* msec */
#define SAV_DEFAULT_SCAN_ARCHIVE		false
#define SAV_DEFAULT_MAX_NESTED_SCAN_ARCHIVE	1
#define SAV_DEFAULT_SCAN_MIME			false
/* Default values for module-specific configuration variables */
#define SAV_DEFAULT_FSAV_PROTOCOL		5 /* F-Secure Linux 7 or later? */
#define SAV_DEFAULT_SCAN_RISKWARE		false
#define SAV_DEFAULT_STOP_SCAN_ON_FIRST		true
#define SAV_DEFAULT_FILTER_FILENAME		false

#define SAV_MODULE_CONFIG_MEMBERS \
	int fsav_protocol; \
	bool scan_riskware; \
	bool stop_scan_on_first; \
	bool filter_filename; \
	/* End of SAV_MODULE_CONFIG_MEMBERS */

#define sav_module_connect			sav_fsav_connect
#define sav_module_destruct_config		sav_fsav_destruct_config
#define sav_module_scan_init			sav_fsav_scan_init
#define sav_module_scan_end			sav_fsav_scan_end
#define sav_module_scan				sav_fsav_scan

#include "sav-vfs.h"

/* ====================================================================== */

#include "sav-utils.h"

/* ====================================================================== */

static sav_result sav_fsav_scan_init(sav_handle *sav_h)
{
	sav_io_handle *io_h = sav_h->io_h;
	sav_result result;

	if (io_h->socket != -1) {
		/* Check if the currect connection is available */
		/* FIXME: I don't know the correct PING command format... */
		if (sav_io_writeread(io_h, "PING") == SAV_RESULT_OK) {
			if (strn_eq(io_h->r_buffer, "ERROR\t", 6)) {
				DEBUG(10,("Re-using existent fsavd connection\n"));
				return SAV_RESULT_OK;
			}
		}

		DEBUG(10,("Closing unavailable fsavd connection\n"));

		sav_fsav_scan_end(sav_h);
	}

	DEBUG(10,("Connecting to fsavd socket: %s\n", sav_h->socket_path));

	become_root();
	result = sav_io_connect_path(io_h, sav_h->socket_path);
	unbecome_root();

	if (result != SAV_RESULT_OK) {
		DEBUG(0,("Connecting to fsavd socket failed: %s: %s\n",
			sav_h->socket_path, strerror(errno)));
		return SAV_RESULT_ERROR;
	}

	if (sav_io_read(io_h) != SAV_RESULT_OK) {
		DEBUG(0,("Reading fsavd greeting message failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "DBVERSION\t", 10)) {
		DEBUG(0,("Invalid fsavd greeting message: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

	if (sav_io_writeread(io_h,
	    "PROTOCOL\t%d", sav_h->fsav_protocol)
	    != SAV_RESULT_OK) {
		DEBUG(0,("PROTOCOL failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("PROTOCOL failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

#if 0 /* FIXME */
	if (sav_io_writeread(io_h,
	    "CONFIGURE\tTIMEOUT\t%d", sav_h->timeout / 1000)
	    != SAV_RESULT_OK) {
		DEBUG(0,("CONFIGURE TIMEOUT failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("CONFIGURE TIMEOUT failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}
#endif

	if (sav_io_writeread(io_h,
	    "CONFIGURE\tSTOPONFIRST\t%d", sav_h->stop_scan_on_first ? 1 : 0)
	    != SAV_RESULT_OK) {
		DEBUG(0,("CONFIGURE STOPONFIRST failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("CONFIGURE STOPONFIRST failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

	if (sav_io_writeread(io_h,
	    "CONFIGURE\tFILTER\t%d", sav_h->filter_filename ? 1 : 0)
	    != SAV_RESULT_OK) {
		DEBUG(0,("CONFIGURE FILTER failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("CONFIGURE FILTER failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

	if (sav_io_writeread(io_h,
	    "CONFIGURE\tARCHIVE\t%d", sav_h->scan_archive ? 1 : 0)
	    != SAV_RESULT_OK) {
		DEBUG(0,("CONFIGURE ARCHIVE failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("CONFIGURE ARCHIVE failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

	if (sav_io_writeread(io_h,
	    "CONFIGURE\tMAXARCH\t%d", sav_h->max_nested_scan_archive)
	    != SAV_RESULT_OK) {
		DEBUG(0,("CONFIGURE MAXARCH failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("CONFIGURE MAXARCH failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

	if (sav_io_writeread(io_h,
	    "CONFIGURE\tMIME\t%d", sav_h->scan_mime ? 1 : 0)
	    != SAV_RESULT_OK) {
		DEBUG(0,("CONFIGURE MIME failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("CONFIGURE MIME failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

	if (sav_io_writeread(io_h,
	    "CONFIGURE\tRISKWARE\t%d", sav_h->scan_riskware ? 1 : 0)
	    != SAV_RESULT_OK) {
		DEBUG(0,("CONFIGURE RISKWARE failed: %s\n", strerror(errno)));
		goto sav_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("CONFIGURE RISKWARE failed: %s\n", io_h->r_buffer));
		goto sav_fsav_init_failed;
	}

	return SAV_RESULT_OK;

sav_fsav_init_failed:

	sav_fsav_scan_end(sav_h);

	return SAV_RESULT_ERROR;
}

static void sav_fsav_scan_end(sav_handle *sav_h)
{
	sav_io_handle *io_h = sav_h->io_h;

	sav_io_disconnect(io_h);
}

static sav_result sav_fsav_scan(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *filepath,
	const char **reportp)
{
	sav_io_handle *io_h = sav_h->io_h;
	sav_result result = SAV_RESULT_CLEAN;
	const char *report = NULL;
	char *report_token, *report_saveptr;

	if (sav_io_writeread(io_h, "SCAN\t%s", filepath) != SAV_RESULT_OK) {
		DEBUG(0,("SCAN failed: %s\n", strerror(errno)));
		result = SAV_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"SCAN failed: %s\n", strerror(errno));
		goto sav_fsav_scan_return;
	}

	while (true) {
		report_token = strtok_r(io_h->r_buffer, "\t", &report_saveptr);

		if (str_eq(report_token, "OK") ) {
			break;
		} else if (str_eq(report_token, "CLEAN") ) {
			/* CLEAN\t<FILEPATH>\n */
			result = SAV_RESULT_CLEAN;
			report = "Clean";
		} else if (str_eq(report_token, "INFECTED") ||
			   str_eq(report_token, "ARCHIVE_INFECTED") ||
		           str_eq(report_token, "MIME_INFECTED") ||
			   str_eq(report_token, "RISKWARE") ||
			   str_eq(report_token, "ARCHIVE_RISKWARE") ||
			   str_eq(report_token, "MIME_RISKWARE")) {
			/* INFECTED\t<FILEPATH>\t<DESCRIPTION>\t<ENGINE>\n */
			result = SAV_RESULT_INFECTED;
			report_token = strtok_r(NULL, "\t", &report_saveptr);
			report_token = strtok_r(NULL, "\t", &report_saveptr);
			if (report_token) {
				  report = report_token;
			} else {
				  report = "UNKNOWN INFECTION";
			}
		} else if (str_eq(report_token, "OPEN_ARCHIVE")) {
			/* Ignore */
		} else if (str_eq(report_token, "CLOSE_ARCHIVE")) {
			/* Ignore */
		} else if (str_eq(report_token, "SUSPECTED") ||
			   str_eq(report_token, "ARCHIVE_SUSPECTED") ||
			   str_eq(report_token, "MIME_SUSPECTED")) {
			/* Ignore */
#if 0
			/* FIXME: Block if "block suspected file" option is true */
			result = SAV_RESULT_SUSPECTED;
			...
#endif
		} else if (str_eq(report_token, "SCAN_FAILURE")) {
			/* SCAN_FAILURE\t<FILEPATH>\t0x<CODE>\t<DESCRIPTION> [<ENGINE>]\n */
			result = SAV_RESULT_ERROR;
			report_token = strtok_r(NULL, "\t", &report_saveptr);
			report_token = strtok_r(NULL, "\t", &report_saveptr);
			if (report_token) {
				  report = report_token;
			} else {
				  report = "UNKNOWN ERROR";
			}
		} else {
			result = SAV_RESULT_ERROR;
			report = talloc_asprintf(talloc_tos(),
				"Invalid command reply from fsavd: %s\t", report_token);
			if (!report) {
				DEBUG(0,("talloc_asprintf failed\n"));
			}
		}

		if (sav_io_read(io_h) != SAV_RESULT_OK) {
			DEBUG(0,("Reading command reply from fsavd failed: %s\n",
				strerror(errno)));
			break;
		}
	}

sav_fsav_scan_return:

	*reportp = report;

	return result;
}

static int sav_fsav_connect(
	vfs_handle_struct *vfs_h,
	sav_handle *sav_h,
	const char *svc,
	const char *user)
{
	int snum = SNUM(vfs_h->conn);

        sav_h->fsav_protocol = lp_parm_int(
		snum, SAV_MODULE_NAME,
		"fsav protocol",
		SAV_DEFAULT_FSAV_PROTOCOL);

        sav_h->scan_riskware = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"scan riskware",
		SAV_DEFAULT_SCAN_RISKWARE);

        sav_h->stop_scan_on_first = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"stop scan on first",
		SAV_DEFAULT_STOP_SCAN_ON_FIRST);

        sav_h->filter_filename = lp_parm_bool(
		snum, SAV_MODULE_NAME,
		"filter filename",
		SAV_DEFAULT_FILTER_FILENAME);

	return 0;
}

static int sav_fsav_destruct_config(sav_handle *sav_h)
{
	sav_fsav_scan_end(sav_h);

	return 0;
}

