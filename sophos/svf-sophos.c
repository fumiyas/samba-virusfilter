/*
   Samba-VirusFilter VFS modules
   Sophos Anti-Virus savdid (SSSP/1.0) support
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

#define SVF_MODULE_ENGINE "sophos"

/* Default values for standard "extra" configuration variables */
#ifdef SOPHOS_DEFAULT_SOCKET_PATH
#  define SVF_DEFAULT_SOCKET_PATH		SOPHOS_DEFAULT_SOCKET_PATH
#else
#  define SVF_DEFAULT_SOCKET_PATH		"/var/run/savdi/sssp.sock"
#endif
#define SVF_DEFAULT_CONNECT_TIMEOUT		30000 /* msec */
#define SVF_DEFAULT_TIMEOUT			60000 /* msec */
#define SVF_DEFAULT_SCAN_REQUEST_LIMIT		0
#define SVF_DEFAULT_SCAN_ARCHIVE		false
/* Default values for module-specific configuration variables */
/* None */

#define svf_module_connect			svf_sophos_connect
#define svf_module_scan_init			svf_sophos_scan_init
#define svf_module_scan_end			svf_sophos_scan_end
#define svf_module_scan				svf_sophos_scan

#include "svf-vfs.h"

/* ====================================================================== */

#include "svf-utils.h"

/* ====================================================================== */

static int svf_sophos_connect(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const char *svc,
	const char *user)
{
        svf_io_set_readl_eol(svf_h->io_h, "\x0D\x0A", 2);

	return 0;
}

static svf_result svf_sophos_scan_ping(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;

	/* SSSP/1.0 has no "PING" command */
	if (svf_io_writel(io_h, "SSSP/1.0 OPTIONS\n", 17) != SVF_RESULT_OK) {
		return SVF_RESULT_ERROR;
	}

	for (;;) {
		if (svf_io_readl(io_h) != SVF_RESULT_OK) {
			return SVF_RESULT_ERROR;
		}
		if (str_eq(io_h->r_buffer, "")) {
			break;
		}
	}

	return SVF_RESULT_OK;
}

static svf_result svf_sophos_scan_init(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result;

	if (io_h->socket != -1) {
		DEBUG(10,("SSSP: Checking if connection is alive\n"));

		if (svf_sophos_scan_ping(svf_h) == SVF_RESULT_OK) {
			DEBUG(10,("SSSP: Re-using existent connection\n"));
			return SVF_RESULT_OK;
		}

		DEBUG(7,("SSSP: Closing dead connection\n"));
		svf_sophos_scan_end(svf_h);
	}


	DEBUG(7,("SSSP: Connecting to socket: %s\n", svf_h->socket_path));

	become_root();
	result = svf_io_connect_path(io_h, svf_h->socket_path);
	unbecome_root();

	if (result != SVF_RESULT_OK) {
		DEBUG(0,("SSSP: Connecting to socket failed: %s: %s\n",
			svf_h->socket_path, strerror(errno)));
		return SVF_RESULT_ERROR;
	}

	if (svf_io_readl(io_h) != SVF_RESULT_OK) {
		DEBUG(0,("SSSP: Reading greeting message failed: %s\n", strerror(errno)));
		goto svf_sophos_scan_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "OK SSSP/1.0", 11)) {
		DEBUG(0,("SSSP: Invalid greeting message: %s\n", io_h->r_buffer));
		goto svf_sophos_scan_init_failed;
	}

	DEBUG(10,("SSSP: Connected\n"));

	DEBUG(7,("SSSP: Configuring\n"));

	if (svf_io_writefl_readl(io_h,
	    "SSSP/1.0 OPTIONS\n"
	    "output:brief\n"
	    "savigrp:GrpArchiveUnpack %d\n",
	    svf_h->scan_archive ? 1 : 0)
	    != SVF_RESULT_OK) {
		DEBUG(0,("SSSP: OPTIONS: I/O error: %s\n", strerror(errno)));
		goto svf_sophos_scan_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "ACC ", 4)) {
		DEBUG(0,("SSSP: OPTIONS: Not accepted: %s\n", io_h->r_buffer));
		goto svf_sophos_scan_init_failed;
	}
	if (svf_io_readl(io_h) != SVF_RESULT_OK) {
		DEBUG(0,("SSSP: OPTIONS: Read error: %s\n", strerror(errno)));
		goto svf_sophos_scan_init_failed;
	}
	if (!strn_eq(io_h->r_buffer, "DONE OK ", 8)) {
		DEBUG(0,("SSSP: OPTIONS failed: %s\n", io_h->r_buffer));
		goto svf_sophos_scan_init_failed;
	}
	if (svf_io_readl(io_h) != SVF_RESULT_OK) {
		DEBUG(0,("SSSP: OPTIONS: Read error: %s\n", strerror(errno)));
		goto svf_sophos_scan_init_failed;
	}
	if (!str_eq(io_h->r_buffer, "")) {
		DEBUG(0,("SSSP: OPTIONS: Invalid reply: %s\n", io_h->r_buffer));
		goto svf_sophos_scan_init_failed;
	}

	DEBUG(10,("SSSP: Configured\n"));

	return SVF_RESULT_OK;

svf_sophos_scan_init_failed:

	svf_sophos_scan_end(svf_h);

	return SVF_RESULT_ERROR;
}

static void svf_sophos_scan_end(svf_handle *svf_h)
{
	svf_io_handle *io_h = svf_h->io_h;

	DEBUG(7,("SSSP: Disconnecting\n"));

	svf_io_disconnect(io_h);
}

static svf_result svf_sophos_scan(
	vfs_handle_struct *vfs_h,
	svf_handle *svf_h,
	const struct smb_filename *smb_fname,
	const char **reportp)
{
	const char *connectpath = vfs_h->conn->connectpath;
	const char *fname = smb_fname->base_name;
	char fileurl[SVF_IO_URL_MAX+1];
	int fileurl_len, fileurl_len2;
	svf_io_handle *io_h = svf_h->io_h;
	svf_result result = SVF_RESULT_ERROR;
	const char *report = NULL;
	char *reply_token, *reply_saveptr;

	DEBUG(7,("Scanning file: %s/%s\n", connectpath, fname));

	fileurl_len = svf_url_quote(connectpath, fileurl, SVF_IO_URL_MAX);
	if (fileurl_len < 0) {
		DEBUG(0,("svf_url_quote failed: File path too long: %s/%s\n",
			connectpath, fname));
		result = SVF_RESULT_ERROR;
		report = "File path too long";
		goto svf_sophos_scan_return;
	}
	fileurl[fileurl_len] = '/';
	fileurl_len++;

	fileurl_len += fileurl_len2 = svf_url_quote(fname,
		fileurl + fileurl_len, SVF_IO_URL_MAX - fileurl_len);
	if (fileurl_len2 < 0) {
		DEBUG(0,("svf_url_quote failed: File path too long: %s/%s\n",
			connectpath, fname));
		result = SVF_RESULT_ERROR;
		report = "File path too long";
		goto svf_sophos_scan_return;
	}
	fileurl_len += fileurl_len2;

	if (svf_io_writevl(io_h,
	    "SSSP/1.0 SCANFILE ", 18,
	    fileurl, fileurl_len,
	    NULL
	    ) != SVF_RESULT_OK) {
		DEBUG(0,("SSSP: SCANFILE: Write error: %s\n", strerror(errno)));
		goto svf_sophos_scan_io_error;
	}

	if (svf_io_readl(io_h) != SVF_RESULT_OK) {
		DEBUG(0,("SSSP: SCANFILE: Read error: %s\n", strerror(errno)));
		goto svf_sophos_scan_io_error;
	}
	if (!strn_eq(io_h->r_buffer, "ACC ", 4)) {
		DEBUG(0,("SSSP: SCANFILE: Not accepted: %s\n", io_h->r_buffer));
		result = SVF_RESULT_ERROR;
		goto svf_sophos_scan_return;
	}

	result = SVF_RESULT_CLEAN;
	for (;;) {
		if (svf_io_readl(io_h) != SVF_RESULT_OK) {
			DEBUG(0,("SSSP: SCANFILE: Read error: %s\n", strerror(errno)));
			goto svf_sophos_scan_io_error;
		}

		if (str_eq(io_h->r_buffer, "") ) {
			break;
		}

		reply_token = strtok_r(io_h->r_buffer, " ", &reply_saveptr);

		if (str_eq(reply_token, "VIRUS")) {
			result = SVF_RESULT_INFECTED;
			reply_token = strtok_r(NULL, " ", &reply_saveptr);
			if (reply_token) {
				  report = talloc_strdup(talloc_tos(), reply_token);
			} else {
				  report = "UNKNOWN INFECTION";
			}
		} else if (str_eq(reply_token, "OK")) {
			/* Ignore */
		} else if (str_eq(reply_token, "DONE")) {
			reply_token = strtok_r(NULL, "", &reply_saveptr);
			if (reply_token &&
			    !strn_eq(reply_token, "OK 0000 ", 8) && /* Succeed */
			    !strn_eq(reply_token, "OK 0203 ", 8)) { /* Infected */
				DEBUG(0,("SSSP: SCANFILE: Error: %s\n", reply_token));
				result = SVF_RESULT_ERROR;
				report = talloc_asprintf(talloc_tos(),
					"Scanner error: %s\n", reply_token);
			}
		} else {
			DEBUG(0,("SSSP: SCANFILE: Invalid reply: %s\n", reply_token));
			result = SVF_RESULT_ERROR;
			report = "Scanner communication error";
		}
	}

svf_sophos_scan_return:
	*reportp = report;

	return result;

svf_sophos_scan_io_error:
	*reportp = talloc_asprintf(talloc_tos(),
		"Scanner I/O error: %s\n", strerror(errno));

	return result;
}

