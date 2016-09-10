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

#define VIRUSFILTER_MODULE_ENGINE "clamav"

/* Default values for standard "extra" configuration variables */
#ifdef CLAMAV_DEFAULT_SOCKET_PATH
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	CLAMAV_DEFAULT_SOCKET_PATH
#else
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	"/var/run/clamav/clamd.ctl"
#endif
#define VIRUSFILTER_DEFAULT_CONNECT_TIMEOUT	30000 /* msec */
#define VIRUSFILTER_DEFAULT_TIMEOUT		60000 /* msec */
/* Default values for module-specific configuration variables */
/* None */

#define virusfilter_module_connect		virusfilter_clamav_connect
#define virusfilter_module_scan_init		virusfilter_clamav_scan_init
#define virusfilter_module_scan_end		virusfilter_clamav_scan_end
#define virusfilter_module_scan			virusfilter_clamav_scan

#include "vfs_virusfilter_vfs.c"

/* ====================================================================== */

#include "vfs_virusfilter_utils.h"

/* ====================================================================== */

static int virusfilter_clamav_connect(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const char *svc,
	const char *user)
{
	/* To use clamd "zXXXX" commands */
        virusfilter_io_set_writel_eol(virusfilter_h->io_h, "\0", 1);
        virusfilter_io_set_readl_eol(virusfilter_h->io_h, "\0", 1);

	return 0;
}

static virusfilter_result virusfilter_clamav_scan_init(
	virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result;

	DEBUG(7,("clamd: Connecting to socket: %s\n",
		virusfilter_h->socket_path));

	become_root();
	result = virusfilter_io_connect_path(io_h, virusfilter_h->socket_path);
	unbecome_root();

	if (result != VIRUSFILTER_RESULT_OK) {
		DEBUG(0,("clamd: Connecting to socket failed: %s: %s\n",
			virusfilter_h->socket_path, strerror(errno)));
		return VIRUSFILTER_RESULT_ERROR;
	}

	DEBUG(7,("clamd: Connected\n"));

	return VIRUSFILTER_RESULT_OK;
}

static void virusfilter_clamav_scan_end(virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;

	DEBUG(7,("clamd: Disconnecting\n"));

	virusfilter_io_disconnect(io_h);
}

static virusfilter_result virusfilter_clamav_scan(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char **reportp)
{
	const char *connectpath = vfs_h->conn->connectpath;
	const char *fname = smb_fname->base_name;
	size_t filepath_len = strlen(connectpath) + 1 /* slash */ + strlen(fname);
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result = VIRUSFILTER_RESULT_CLEAN;
	char *report = NULL;
	char *reply;
	char *reply_token;

	DEBUG(7,("Scanning file: %s/%s\n", connectpath, fname));

	if (virusfilter_io_writefl_readl(io_h, "zSCAN %s/%s",
	    connectpath, fname) != VIRUSFILTER_RESULT_OK) {
		DEBUG(0,("clamd: zSCAN: I/O error: %s\n", strerror(errno)));
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scanner I/O error: %s\n", strerror(errno));
		goto virusfilter_clamav_scan_return;
	}

	if (io_h->r_buffer[filepath_len] != ':' ||
	    io_h->r_buffer[filepath_len+1] != ' ')
	{
		DEBUG(0,("clamd: zSCAN: Invalid reply: %s\n", io_h->r_buffer));
		result = VIRUSFILTER_RESULT_ERROR;
		report = "Scanner communication error";
		goto virusfilter_clamav_scan_return;
	}
	reply = io_h->r_buffer + filepath_len + 2;

	reply_token = strrchr(io_h->r_buffer, ' ');
	if (!reply_token) {
		DEBUG(0,("clamd: zSCAN: Invalid reply: %s\n", io_h->r_buffer));
		result = VIRUSFILTER_RESULT_ERROR;
		report = "Scanner communication error";
		goto virusfilter_clamav_scan_return;
	}
	*reply_token = '\0';
	reply_token++;

	if (str_eq(reply_token, "OK") ) {
		/* <FILEPATH>: OK */
		result = VIRUSFILTER_RESULT_CLEAN;
		report = "Clean";
	} else if (str_eq(reply_token, "FOUND")) {
		/* <FILEPATH>: <REPORT> FOUND */
		result = VIRUSFILTER_RESULT_INFECTED;
		report = talloc_strdup(talloc_tos(), reply);
	} else if (str_eq(reply_token, "ERROR")) {
		/* <FILEPATH>: <REPORT> ERROR */
		DEBUG(0,("clamd: zSCAN: Error: %s\n", reply));
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scanner error: %s\t", reply);
	} else {
		DEBUG(0,("clamd: zSCAN: Invalid reply: %s\n", reply_token));
		result = VIRUSFILTER_RESULT_ERROR;
		report = "Scanner communication error";
	}

virusfilter_clamav_scan_return:
	if (report == NULL) *reportp = "Scanner report memory error";
	else *reportp = report;

	return result;
}

