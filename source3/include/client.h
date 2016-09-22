/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Jeremy Allison 1998

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

#ifndef _CLIENT_H
#define _CLIENT_H

#define CLI_BUFFER_SIZE SMB_BUFFER_SIZE_MAX

/* default client timeout to 20 seconds on most commands */
#define CLIENT_TIMEOUT (20 * 1000)

/*
 * These definitions depend on smb.h
 */

struct print_job_info {
	uint16_t id;
	uint16_t priority;
	size_t size;
	fstring user;
	fstring name;
	time_t t;
};

struct smbXcli_conn;
struct smbXcli_session;

struct cli_state {
	/**
	 * A list of subsidiary connections for DFS.
	 */
        struct cli_state *prev, *next;
	int rap_error;
	NTSTATUS raw_status; /* maybe via NT_STATUS_DOS() */
	bool map_dos_errors;

	/*
	 * The following strings are the
	 * ones returned by the server if
	 * the protocol > NT1.
	 */
	char *server_type;
	char *server_os;
	char *server_domain;

	char *share;
	char *dev;

	int timeout; /* in milliseconds. */
	int initialised;
	int win95;
	/* What the server offered. */
	uint32_t server_posix_capabilities;
	/* What the client requested. */
	uint32_t requested_posix_capabilities;
	bool backup_intent;

	/* The list of pipes currently open on this connection. */
	struct rpc_pipe_client *pipe_list;

	bool use_kerberos;
	bool fallback_after_kerberos;
	bool use_ccache;
	bool pw_nt_hash;
	bool got_kerberos_mechanism; /* Server supports krb5 in SPNEGO. */

	bool use_oplocks; /* should we use oplocks? */

	/* Where (if anywhere) this is mounted under DFS. */
	char *dfs_mountpoint;

	struct smbXcli_conn *conn;
	const char *remote_realm;

	struct {
		uint32_t pid;
		uint16_t vc_num;
		struct smbXcli_session *session;
		struct smbXcli_tcon *tcon;
	} smb1;

	struct {
		struct smbXcli_session *session;
		struct smbXcli_tcon *tcon;
		struct idr_context *open_handles;
	} smb2;
};

struct file_info {
	uint64_t size;
	uint16_t mode;
	uid_t uid;
	gid_t gid;
	/* these times are normally kept in GMT */
	struct timespec mtime_ts;
	struct timespec atime_ts;
	struct timespec ctime_ts;
	char *name;
	char *short_name;
};

#define CLI_FULL_CONNECTION_DONT_SPNEGO 0x0001
#define CLI_FULL_CONNECTION_USE_KERBEROS 0x0002
#define CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK 0x0004
#define CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS 0x0008
#define CLI_FULL_CONNECTION_OPLOCKS 0x0010
#define CLI_FULL_CONNECTION_LEVEL_II_OPLOCKS 0x0020
#define CLI_FULL_CONNECTION_USE_CCACHE 0x0040
#define CLI_FULL_CONNECTION_FORCE_DOS_ERRORS 0x0080
#define CLI_FULL_CONNECTION_FORCE_ASCII 0x0100
#define CLI_FULL_CONNECTION_USE_NT_HASH 0x0200

#endif /* _CLIENT_H */
