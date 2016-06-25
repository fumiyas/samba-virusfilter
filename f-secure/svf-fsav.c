/*
   Samba-VirusFilter VFS modules
   F-Secure Anti-Virus fsavd support
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

#define SVF_MODULE_ENGINE "fsav"

/* Default values for standard "extra" configuration variables */
#define SVF_DEFAULT_SOCKET_PATH			"/tmp/.fsav-0"
#define SVF_DEFAULT_CONNECT_TIMEOUT		30000 /* msec */
#define SVF_DEFAULT_TIMEOUT			60000 /* msec */
#define SVF_DEFAULT_SCAN_ARCHIVE		false
#define SVF_DEFAULT_MAX_NESTED_SCAN_ARCHIVE	1
#define SVF_DEFAULT_SCAN_REQUEST_LIMIT		0
#define SVF_DEFAULT_SCAN_MIME			false
/* Default values for module-specific configuration variables */
#define SVF_DEFAULT_FSAV_PROTOCOL		5 /* F-Secure Linux 7 or later? */
#define SVF_DEFAULT_SCAN_RISKWARE		false
#define SVF_DEFAULT_STOP_SCAN_ON_FIRST		true
#define SVF_DEFAULT_FILTER_FILENAME		false

#define SVF_MODULE_CONFIG_MEMBERS \
	int fsav_protocol; \
	bool scan_riskware; \
	bool stop_scan_on_first; \
	bool filter_filename; \
	/* End of SVF_MODULE_CONFIG_MEMBERS */

#define svf_module_connect			svf_fsav_connect
#define svf_module_destruct_config		svf_fsav_destruct_config
#define svf_module_scan_init			svf_fsav_scan_init
#define svf_module_scan_end			svf_fsav_scan_end
#define svf_module_scan				svf_fsav_scan

#include "svf-vfs.h"

/* ====================================================================== */

#include "svf-utils.h"

/* ====================================================================== */

static int svf_fsav_connect(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const char *svc,
	const char *user)
{
	int snum = SNUM(vfs_h->conn);

        svf_h->fsav_protocol = lp_parm_int(
		snum, SVF_MODULE_NAME,
		"fsav protocol",
		SVF_DEFAULT_FSAV_PROTOCOL);

        svf_h->scan_riskware = lp_parm_bool(
		snum, SVF_MODULE_NAME,
		"scan riskware",
		SVF_DEFAULT_SCAN_RISKWARE);

        svf_h->stop_scan_on_first = lp_parm_bool(
		snum, SVF_MODULE_NAME,
		"stop scan on first",
		SVF_DEFAULT_STOP_SCAN_ON_FIRST);

        svf_h->filter_filename = lp_parm_bool(
		snum, SVF_MODULE_NAME,
		"filter filename",
		SVF_DEFAULT_FILTER_FILENAME);

	return 0;
}

static int svf_fsav_destruct_config(svf_handle *svf_h)
{
	svf_fsav_scan_end(svf_h);

	return 0;
}

static svf_result svf_fsav_scan_init(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result;

	if (io_h->socket != -1) {
		DEBUG(10,("fsavd: Checking if connection is alive\n"));

		/* FIXME: I don't know the correct PING command format... */
		if (svf_io_writefl_readl(io_h, "PING") == SVF_RESULT_OK) {
			if (strn_eq(io_h->r_buffer, "ERROR\t", 6)) {
				DEBUG(10,("fsavd: Re-using existent connection\n"));
				return SVF_RESULT_OK;
			}
		}

		DEBUG(10,("fsavd: Closing dead connection\n"));
		svf_fsav_scan_end(svf_h);
	}

	DEBUG(7,("fsavd: Connecting to socket: %s\n", svf_h->socket_path));

	become_root();
	result = svf_io_connect_path(io_h, svf_h->socket_path);
	unbecome_root();

	if (result != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: Connecting to socket failed: %s: %s\n",
			svf_h->socket_path, strerror(errno)));
		return SVF_RESULT_ERROR;
	}

	if (svf_io_readl(io_h) != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: Reading greeting message failed: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "DBVERSION\t", 10)) {
		DEBUG(0,("fsavd: Invalid greeting message: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

	DEBUG(10,("fsavd: Connected\n"));

	DEBUG(7,("fsavd: Configuring\n"));

	if (svf_io_writefl_readl(io_h,
	    "PROTOCOL\t%d", svf_h->fsav_protocol)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: PROTOCOL: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: PROTOCOL: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

#if 0 /* FIXME */
	if (svf_io_writefl_readl(io_h,
	    "CONFIGURE\tTIMEOUT\t%d", svf_h->timeout / 1000)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: CONFIGURE TIMEOUT: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: CONFIGURE TIMEOUT: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}
#endif

	if (svf_io_writefl_readl(io_h,
	    "CONFIGURE\tSTOPONFIRST\t%d", svf_h->stop_scan_on_first ? 1 : 0)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: CONFIGURE STOPONFIRST: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: CONFIGURE STOPONFIRST: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

	if (svf_io_writefl_readl(io_h,
	    "CONFIGURE\tFILTER\t%d", svf_h->filter_filename ? 1 : 0)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: CONFIGURE FILTER: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: CONFIGURE FILTER: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

	if (svf_io_writefl_readl(io_h,
	    "CONFIGURE\tARCHIVE\t%d", svf_h->scan_archive ? 1 : 0)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: CONFIGURE ARCHIVE: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: CONFIGURE ARCHIVE: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

	if (svf_io_writefl_readl(io_h,
	    "CONFIGURE\tMAXARCH\t%d", svf_h->max_nested_scan_archive)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: CONFIGURE MAXARCH: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: CONFIGURE MAXARCH: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

	if (svf_io_writefl_readl(io_h,
	    "CONFIGURE\tMIME\t%d", svf_h->scan_mime ? 1 : 0)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: CONFIGURE MIME: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: CONFIGURE MIME: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

	if (svf_io_writefl_readl(io_h,
	    "CONFIGURE\tRISKWARE\t%d", svf_h->scan_riskware ? 1 : 0)
	    != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: CONFIGURE RISKWARE: I/O error: %s\n", strerror(errno)));
		goto svf_fsav_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK\t", 3)) {
		DEBUG(0,("fsavd: CONFIGURE RISKWARE: Not accepted: %s\n", io_h->r_buffer));
		goto svf_fsav_init_failed;
	}

	DEBUG(10,("fsavd: Configured\n"));

	return SVF_RESULT_OK;

svf_fsav_init_failed:
	svf_fsav_scan_end(svf_h);

	return SVF_RESULT_ERROR;
}

static void svf_fsav_scan_end(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;

	DEBUG(7,("fsavd: Disconnecting\n"));
	svf_io_disconnect(io_h);
}

static svf_result svf_fsav_scan(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const struct smb_filename *smb_fname,
	const char **reportp)
{
	const char *connectpath = vfs_h->conn->connectpath;
	const char *fname = smb_fname->base_name;
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result = SVF_RESULT_CLEAN;
	const char *report = NULL;
	char *reply_token, *reply_saveptr;

	DEBUG(7,("Scanning file: %s/%s\n", connectpath, fname));

	if (svf_io_writevl(io_h,
	    "SCAN\t", 5,
	    connectpath, (int)strlen(connectpath),
	    "/", 1,
	    fname, (int)strlen(fname),
	    NULL) != SVF_RESULT_OK) {
		DEBUG(0,("fsavd: SCAN: Write error: %s\n", strerror(errno)));
		result = SVF_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scanner I/O error: %s\n", strerror(errno));
		goto svf_fsav_scan_return;
	}

	for (;;) {
		if (svf_io_readl(io_h) != SVF_RESULT_OK) {
			DEBUG(0,("fsavd: SCANFILE: Read error: %s\n",
				strerror(errno)));
			result = SVF_RESULT_ERROR;
			report = talloc_asprintf(talloc_tos(),
				"Scanner I/O error: %s\n", strerror(errno));
			break;
		}

		reply_token = strtok_r(io_h->r_buffer, "\t", &reply_saveptr);

		if (str_eq(reply_token, "OK") ) {
			break;
		} else if (str_eq(reply_token, "CLEAN") ) {
			/* CLEAN\t<FILEPATH> */
			result = SVF_RESULT_CLEAN;
			report = "Clean";
		} else if (str_eq(reply_token, "INFECTED") ||
			   str_eq(reply_token, "ARCHIVE_INFECTED") ||
		           str_eq(reply_token, "MIME_INFECTED") ||
			   str_eq(reply_token, "RISKWARE") ||
			   str_eq(reply_token, "ARCHIVE_RISKWARE") ||
			   str_eq(reply_token, "MIME_RISKWARE")) {
			/* INFECTED\t<FILEPATH>\t<REPORT>\t<ENGINE> */
			result = SVF_RESULT_INFECTED;
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			if (reply_token) {
				  report = talloc_strdup(talloc_tos(), reply_token);
			} else {
				  report = "UNKNOWN INFECTION";
			}
		} else if (str_eq(reply_token, "OPEN_ARCHIVE")) {
			/* Ignore */
		} else if (str_eq(reply_token, "CLOSE_ARCHIVE")) {
			/* Ignore */
		} else if (str_eq(reply_token, "SUSPECTED") ||
			   str_eq(reply_token, "ARCHIVE_SUSPECTED") ||
			   str_eq(reply_token, "MIME_SUSPECTED")) {
#if 0
			/* FIXME: Block if "block suspected file" option is true */
			result = SVF_RESULT_SUSPECTED;
			...
#else
			/* Ignore */
#endif
		} else if (str_eq(reply_token, "SCAN_FAILURE")) {
			/* SCAN_FAILURE\t<FILEPATH>\t0x<CODE>\t<REPORT> [<ENGINE>] */
			result = SVF_RESULT_ERROR;
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			DEBUG(0,("fsavd: SCANFILE: Scaner error: %s\n",
				reply_token ? reply_token : "UNKNOWN ERROR"));
			report = talloc_asprintf(talloc_tos(),
				"Scanner error: %s",
				reply_token ? reply_token : "UNKNOWN ERROR");
		} else {
			result = SVF_RESULT_ERROR;
			DEBUG(0,("fsavd: SCANFILE: Invalid reply: %s\t", reply_token));
			report = "Scanner communication error";
		}
	}

svf_fsav_scan_return:
	*reportp = report;

	return result;
}

