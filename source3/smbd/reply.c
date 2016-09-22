/*
   Unix SMB/CIFS implementation.
   Main SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jeremy Allison 1992-2007.
   Copyright (C) Volker Lendecke 2007

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
/*
   This file handles most of the reply_ calls that the server
   makes to handle specific protocols
*/

#include "includes.h"
#include "system/filesys.h"
#include "printing.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "fake_file.h"
#include "rpc_client/rpc_client.h"
#include "../librpc/gen_ndr/ndr_spoolss_c.h"
#include "../librpc/gen_ndr/open_files.h"
#include "rpc_client/cli_spoolss.h"
#include "rpc_client/init_spoolss.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "libcli/security/security.h"
#include "libsmb/nmblib.h"
#include "auth.h"
#include "smbprofile.h"
#include "../lib/tsocket/tsocket.h"
#include "lib/tevent_wait.h"
#include "libcli/smb/smb_signing.h"
#include "lib/util/sys_rw_data.h"

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for a findfirst/findnext
 path or anything including wildcards.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption). '\\' *may* be the second byte in a multibyte char
 set.
****************************************************************************/

/* Custom version for processing POSIX paths. */
#define IS_PATH_SEP(c,posix_only) ((c) == '/' || (!(posix_only) && (c) == '\\'))

static NTSTATUS check_path_syntax_internal(char *path,
					   bool posix_path,
					   bool *p_last_component_contains_wcard)
{
	char *d = path;
	const char *s = path;
	NTSTATUS ret = NT_STATUS_OK;
	bool start_of_name_component = True;
	bool stream_started = false;

	*p_last_component_contains_wcard = False;

	while (*s) {
		if (stream_started) {
			switch (*s) {
			case '/':
			case '\\':
				return NT_STATUS_OBJECT_NAME_INVALID;
			case ':':
				if (s[1] == '\0') {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				if (strchr_m(&s[1], ':')) {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				break;
			}
		}

		if ((*s == ':') && !posix_path && !stream_started) {
			if (*p_last_component_contains_wcard) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
			/* Stream names allow more characters than file names.
			   We're overloading posix_path here to allow a wider
			   range of characters. If stream_started is true this
			   is still a Windows path even if posix_path is true.
			   JRA.
			*/
			stream_started = true;
			start_of_name_component = false;
			posix_path = true;

			if (s[1] == '\0') {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
		}

		if (!stream_started && IS_PATH_SEP(*s,posix_path)) {
			/*
			 * Safe to assume is not the second part of a mb char
			 * as this is handled below.
			 */
			/* Eat multiple '/' or '\\' */
			while (IS_PATH_SEP(*s,posix_path)) {
				s++;
			}
			if ((d != path) && (*s != '\0')) {
				/* We only care about non-leading or trailing '/' or '\\' */
				*d++ = '/';
			}

			start_of_name_component = True;
			/* New component. */
			*p_last_component_contains_wcard = False;
			continue;
		}

		if (start_of_name_component) {
			if ((s[0] == '.') && (s[1] == '.') && (IS_PATH_SEP(s[2],posix_path) || s[2] == '\0')) {
				/* Uh oh - "/../" or "\\..\\"  or "/..\0" or "\\..\0" ! */

				/*
				 * No mb char starts with '.' so we're safe checking the directory separator here.
				 */

				/* If  we just added a '/' - delete it */
				if ((d > path) && (*(d-1) == '/')) {
					*(d-1) = '\0';
					d--;
				}

				/* Are we at the start ? Can't go back further if so. */
				if (d <= path) {
					ret = NT_STATUS_OBJECT_PATH_SYNTAX_BAD;
					break;
				}
				/* Go back one level... */
				/* We know this is safe as '/' cannot be part of a mb sequence. */
				/* NOTE - if this assumption is invalid we are not in good shape... */
				/* Decrement d first as d points to the *next* char to write into. */
				for (d--; d > path; d--) {
					if (*d == '/')
						break;
				}
				s += 2; /* Else go past the .. */
				/* We're still at the start of a name component, just the previous one. */
				continue;

			} else if ((s[0] == '.') && ((s[1] == '\0') || IS_PATH_SEP(s[1],posix_path))) {
				if (posix_path) {
					/* Eat the '.' */
					s++;
					continue;
				}
			}

		}

		if (!(*s & 0x80)) {
			if (!posix_path) {
				if (*s <= 0x1f || *s == '|') {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				switch (*s) {
					case '*':
					case '?':
					case '<':
					case '>':
					case '"':
						*p_last_component_contains_wcard = True;
						break;
					default:
						break;
				}
			}
			*d++ = *s++;
		} else {
			size_t siz;
			/* Get the size of the next MB character. */
			next_codepoint(s,&siz);
			switch(siz) {
				case 5:
					*d++ = *s++;
					/*fall through*/
				case 4:
					*d++ = *s++;
					/*fall through*/
				case 3:
					*d++ = *s++;
					/*fall through*/
				case 2:
					*d++ = *s++;
					/*fall through*/
				case 1:
					*d++ = *s++;
					break;
				default:
					DEBUG(0,("check_path_syntax_internal: character length assumptions invalid !\n"));
					*d = '\0';
					return NT_STATUS_INVALID_PARAMETER;
			}
		}
		start_of_name_component = False;
	}

	*d = '\0';

	return ret;
}

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for regular pathnames.
 No wildcards allowed.
****************************************************************************/

NTSTATUS check_path_syntax(char *path)
{
	bool ignore;
	return check_path_syntax_internal(path, False, &ignore);
}

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for regular pathnames.
 Wildcards allowed - p_contains_wcard returns true if the last component contained
 a wildcard.
****************************************************************************/

NTSTATUS check_path_syntax_wcard(char *path, bool *p_contains_wcard)
{
	return check_path_syntax_internal(path, False, p_contains_wcard);
}

/****************************************************************************
 Check the path for a POSIX client.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption).
****************************************************************************/

NTSTATUS check_path_syntax_posix(char *path)
{
	bool ignore;
	return check_path_syntax_internal(path, True, &ignore);
}

/****************************************************************************
 Pull a string and check the path allowing a wilcard - provide for error return.
 Passes in posix flag.
****************************************************************************/

static size_t srvstr_get_path_wcard_internal(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			bool posix_pathnames,
			NTSTATUS *err,
			bool *contains_wcard)
{
	size_t ret;

	*pp_dest = NULL;

	ret = srvstr_pull_talloc(ctx, base_ptr, smb_flags2, pp_dest, src,
				 src_len, flags);

	if (!*pp_dest) {
		*err = NT_STATUS_INVALID_PARAMETER;
		return ret;
	}

	*contains_wcard = False;

	if (smb_flags2 & FLAGS2_DFS_PATHNAMES) {
		/*
		 * For a DFS path the function parse_dfs_path()
		 * will do the path processing, just make a copy.
		 */
		*err = NT_STATUS_OK;
		return ret;
	}

	if (posix_pathnames) {
		*err = check_path_syntax_posix(*pp_dest);
	} else {
		*err = check_path_syntax_wcard(*pp_dest, contains_wcard);
	}

	return ret;
}

/****************************************************************************
 Pull a string and check the path allowing a wilcard - provide for error return.
****************************************************************************/

size_t srvstr_get_path_wcard(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err,
			bool *contains_wcard)
{
	return srvstr_get_path_wcard_internal(ctx,
			base_ptr,
			smb_flags2,
			pp_dest,
			src,
			src_len,
			flags,
			false,
			err,
			contains_wcard);
}

/****************************************************************************
 Pull a string and check the path allowing a wilcard - provide for error return.
 posix_pathnames version.
****************************************************************************/

size_t srvstr_get_path_wcard_posix(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err,
			bool *contains_wcard)
{
	return srvstr_get_path_wcard_internal(ctx,
			base_ptr,
			smb_flags2,
			pp_dest,
			src,
			src_len,
			flags,
			true,
			err,
			contains_wcard);
}

/****************************************************************************
 Pull a string and check the path - provide for error return.
****************************************************************************/

size_t srvstr_get_path(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err)
{
	bool ignore;
	return srvstr_get_path_wcard_internal(ctx,
			base_ptr,
			smb_flags2,
			pp_dest,
			src,
			src_len,
			flags,
			false,
			err,
			&ignore);
}

/****************************************************************************
 Pull a string and check the path - provide for error return.
 posix_pathnames version.
****************************************************************************/

size_t srvstr_get_path_posix(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err)
{
	bool ignore;
	return srvstr_get_path_wcard_internal(ctx,
			base_ptr,
			smb_flags2,
			pp_dest,
			src,
			src_len,
			flags,
			true,
			err,
			&ignore);
}


size_t srvstr_get_path_req_wcard(TALLOC_CTX *mem_ctx, struct smb_request *req,
				 char **pp_dest, const char *src, int flags,
				 NTSTATUS *err, bool *contains_wcard)
{
	ssize_t bufrem = smbreq_bufrem(req, src);

	if (bufrem < 0) {
		*err = NT_STATUS_INVALID_PARAMETER;
		return 0;
	}

	if (req->posix_pathnames) {
		return srvstr_get_path_wcard_internal(mem_ctx,
				(const char *)req->inbuf,
				req->flags2,
				pp_dest,
				src,
				bufrem,
				flags,
				true,
				err,
				contains_wcard);
	} else {
		return srvstr_get_path_wcard_internal(mem_ctx,
				(const char *)req->inbuf,
				req->flags2,
				pp_dest,
				src,
				bufrem,
				flags,
				false,
				err,
				contains_wcard);
	}
}

size_t srvstr_get_path_req(TALLOC_CTX *mem_ctx, struct smb_request *req,
			   char **pp_dest, const char *src, int flags,
			   NTSTATUS *err)
{
	bool ignore;
	return srvstr_get_path_req_wcard(mem_ctx, req, pp_dest, src,
					 flags, err, &ignore);
}

/**
 * pull a string from the smb_buf part of a packet. In this case the
 * string can either be null terminated or it can be terminated by the
 * end of the smbbuf area
 */
size_t srvstr_pull_req_talloc(TALLOC_CTX *ctx, struct smb_request *req,
			      char **dest, const uint8_t *src, int flags)
{
	ssize_t bufrem = smbreq_bufrem(req, src);

	if (bufrem < 0) {
		return 0;
	}

	return pull_string_talloc(ctx, req->inbuf, req->flags2, dest, src,
				  bufrem, flags);
}

/****************************************************************************
 Check if we have a correct fsp pointing to a file. Basic check for open fsp.
****************************************************************************/

bool check_fsp_open(connection_struct *conn, struct smb_request *req,
		    files_struct *fsp)
{
	if ((fsp == NULL) || (conn == NULL)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return False;
	}
	if ((conn != fsp->conn) || (req->vuid != fsp->vuid)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return False;
	}
	return True;
}

/****************************************************************************
 Check if we have a correct fsp pointing to a file.
****************************************************************************/

bool check_fsp(connection_struct *conn, struct smb_request *req,
	       files_struct *fsp)
{
	if (!check_fsp_open(conn, req, fsp)) {
		return False;
	}
	if (fsp->is_directory) {
		reply_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		return False;
	}
	if (fsp->fh->fd == -1) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		return False;
	}
	fsp->num_smb_operations++;
	return True;
}

/****************************************************************************
 Check if we have a correct fsp pointing to a quota fake file. Replacement for
 the CHECK_NTQUOTA_HANDLE_OK macro.
****************************************************************************/

bool check_fsp_ntquota_handle(connection_struct *conn, struct smb_request *req,
			      files_struct *fsp)
{
	if (!check_fsp_open(conn, req, fsp)) {
		return false;
	}

	if (fsp->is_directory) {
		return false;
	}

	if (fsp->fake_file_handle == NULL) {
		return false;
	}

	if (fsp->fake_file_handle->type != FAKE_FILE_TYPE_QUOTA) {
		return false;
	}

	if (fsp->fake_file_handle->private_data == NULL) {
		return false;
	}

	return true;
}

static bool netbios_session_retarget(struct smbXsrv_connection *xconn,
				     const char *name, int name_type)
{
	char *trim_name;
	char *trim_name_type;
	const char *retarget_parm;
	char *retarget;
	char *p;
	int retarget_type = 0x20;
	int retarget_port = NBT_SMB_PORT;
	struct sockaddr_storage retarget_addr;
	struct sockaddr_in *in_addr;
	bool ret = false;
	uint8_t outbuf[10];

	if (get_socket_port(xconn->transport.sock) != NBT_SMB_PORT) {
		return false;
	}

	trim_name = talloc_strdup(talloc_tos(), name);
	if (trim_name == NULL) {
		goto fail;
	}
	trim_char(trim_name, ' ', ' ');

	trim_name_type = talloc_asprintf(trim_name, "%s#%2.2x", trim_name,
					 name_type);
	if (trim_name_type == NULL) {
		goto fail;
	}

	retarget_parm = lp_parm_const_string(-1, "netbios retarget",
					     trim_name_type, NULL);
	if (retarget_parm == NULL) {
		retarget_parm = lp_parm_const_string(-1, "netbios retarget",
						     trim_name, NULL);
	}
	if (retarget_parm == NULL) {
		goto fail;
	}

	retarget = talloc_strdup(trim_name, retarget_parm);
	if (retarget == NULL) {
		goto fail;
	}

	DEBUG(10, ("retargeting %s to %s\n", trim_name_type, retarget));

	p = strchr(retarget, ':');
	if (p != NULL) {
		*p++ = '\0';
		retarget_port = atoi(p);
	}

	p = strchr_m(retarget, '#');
	if (p != NULL) {
		*p++ = '\0';
		if (sscanf(p, "%x", &retarget_type) != 1) {
			goto fail;
		}
	}

	ret = resolve_name(retarget, &retarget_addr, retarget_type, false);
	if (!ret) {
		DEBUG(10, ("could not resolve %s\n", retarget));
		goto fail;
	}

	if (retarget_addr.ss_family != AF_INET) {
		DEBUG(10, ("Retarget target not an IPv4 addr\n"));
		goto fail;
	}

	in_addr = (struct sockaddr_in *)(void *)&retarget_addr;

	_smb_setlen(outbuf, 6);
	SCVAL(outbuf, 0, 0x84);
	*(uint32_t *)(outbuf+4) = in_addr->sin_addr.s_addr;
	*(uint16_t *)(outbuf+8) = htons(retarget_port);

	if (!srv_send_smb(xconn, (char *)outbuf, false, 0, false,
			  NULL)) {
		exit_server_cleanly("netbios_session_retarget: srv_send_smb "
				    "failed.");
	}

	ret = true;
 fail:
	TALLOC_FREE(trim_name);
	return ret;
}

static void reply_called_name_not_present(char *outbuf)
{
	smb_setlen(outbuf, 1);
	SCVAL(outbuf, 0, 0x83);
	SCVAL(outbuf, 4, 0x82);
}

/****************************************************************************
 Reply to a (netbios-level) special message. 
****************************************************************************/

void reply_special(struct smbXsrv_connection *xconn, char *inbuf, size_t inbuf_size)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	int msg_type = CVAL(inbuf,0);
	int msg_flags = CVAL(inbuf,1);
	/*
	 * We only really use 4 bytes of the outbuf, but for the smb_setlen
	 * calculation & friends (srv_send_smb uses that) we need the full smb
	 * header.
	 */
	char outbuf[smb_size];

	memset(outbuf, '\0', sizeof(outbuf));

	smb_setlen(outbuf,0);

	switch (msg_type) {
	case NBSSrequest: /* session request */
	{
		/* inbuf_size is guarenteed to be at least 4. */
		fstring name1,name2;
		int name_type1, name_type2;
		int name_len1, name_len2;

		*name1 = *name2 = 0;

		if (xconn->transport.nbt.got_session) {
			exit_server_cleanly("multiple session request not permitted");
		}

		SCVAL(outbuf,0,NBSSpositive);
		SCVAL(outbuf,3,0);

		/* inbuf_size is guaranteed to be at least 4. */
		name_len1 = name_len((unsigned char *)(inbuf+4),inbuf_size - 4);
		if (name_len1 <= 0 || name_len1 > inbuf_size - 4) {
			DEBUG(0,("Invalid name length in session request\n"));
			reply_called_name_not_present(outbuf);
			break;
		}
		name_len2 = name_len((unsigned char *)(inbuf+4+name_len1),inbuf_size - 4 - name_len1);
		if (name_len2 <= 0 || name_len2 > inbuf_size - 4 - name_len1) {
			DEBUG(0,("Invalid name length in session request\n"));
			reply_called_name_not_present(outbuf);
			break;
		}

		name_type1 = name_extract((unsigned char *)inbuf,
				inbuf_size,(unsigned int)4,name1);
		name_type2 = name_extract((unsigned char *)inbuf,
				inbuf_size,(unsigned int)(4 + name_len1),name2);

		if (name_type1 == -1 || name_type2 == -1) {
			DEBUG(0,("Invalid name type in session request\n"));
			reply_called_name_not_present(outbuf);
			break;
		}

		DEBUG(2,("netbios connect: name1=%s0x%x name2=%s0x%x\n",
			 name1, name_type1, name2, name_type2));

		if (netbios_session_retarget(xconn, name1, name_type1)) {
			exit_server_cleanly("retargeted client");
		}

		/*
		 * Windows NT/2k uses "*SMBSERVER" and XP uses
		 * "*SMBSERV" arrggg!!!
		 */
		if (strequal(name1, "*SMBSERVER     ")
		    || strequal(name1, "*SMBSERV       "))  {
			char *raddr;

			raddr = tsocket_address_inet_addr_string(sconn->remote_address,
								 talloc_tos());
			if (raddr == NULL) {
				exit_server_cleanly("could not allocate raddr");
			}

			fstrcpy(name1, raddr);
		}

		set_local_machine_name(name1, True);
		set_remote_machine_name(name2, True);

		if (is_ipaddress(sconn->remote_hostname)) {
			char *p = discard_const_p(char, sconn->remote_hostname);

			talloc_free(p);

			sconn->remote_hostname = talloc_strdup(sconn,
						get_remote_machine_name());
			if (sconn->remote_hostname == NULL) {
				exit_server_cleanly("could not copy remote name");
			}
			xconn->remote_hostname = sconn->remote_hostname;
		}

		DEBUG(2,("netbios connect: local=%s remote=%s, name type = %x\n",
			 get_local_machine_name(), get_remote_machine_name(),
			 name_type2));

		if (name_type2 == 'R') {
			/* We are being asked for a pathworks session --- 
			   no thanks! */
			reply_called_name_not_present(outbuf);
			break;
		}

		reload_services(sconn, conn_snum_used, true);
		reopen_logs();

		xconn->transport.nbt.got_session = true;
		break;
	}

	case 0x89: /* session keepalive request 
		      (some old clients produce this?) */
		SCVAL(outbuf,0,NBSSkeepalive);
		SCVAL(outbuf,3,0);
		break;

	case NBSSpositive: /* positive session response */
	case NBSSnegative: /* negative session response */
	case NBSSretarget: /* retarget session response */
		DEBUG(0,("Unexpected session response\n"));
		break;

	case NBSSkeepalive: /* session keepalive */
	default:
		return;
	}

	DEBUG(5,("init msg_type=0x%x msg_flags=0x%x\n",
		    msg_type, msg_flags));

	srv_send_smb(xconn, outbuf, false, 0, false, NULL);

	if (CVAL(outbuf, 0) != 0x82) {
		exit_server_cleanly("invalid netbios session");
	}
	return;
}

/****************************************************************************
 Reply to a tcon.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tcon(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	const char *service;
	char *service_buf = NULL;
	char *password = NULL;
	char *dev = NULL;
	int pwlen=0;
	NTSTATUS nt_status;
	const uint8_t *p;
	const char *p2;
	TALLOC_CTX *ctx = talloc_tos();
	struct smbXsrv_connection *xconn = req->xconn;
	NTTIME now = timeval_to_nttime(&req->request_time);

	START_PROFILE(SMBtcon);

	if (req->buflen < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtcon);
		return;
	}

	p = req->buf + 1;
	p += srvstr_pull_req_talloc(ctx, req, &service_buf, p, STR_TERMINATE);
	p += 1;
	pwlen = srvstr_pull_req_talloc(ctx, req, &password, p, STR_TERMINATE);
	p += pwlen+1;
	p += srvstr_pull_req_talloc(ctx, req, &dev, p, STR_TERMINATE);
	p += 1;

	if (service_buf == NULL || password == NULL || dev == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtcon);
		return;
	}
	p2 = strrchr_m(service_buf,'\\');
	if (p2) {
		service = p2+1;
	} else {
		service = service_buf;
	}

	conn = make_connection(req, now, service, dev,
			       req->vuid,&nt_status);
	req->conn = conn;

	if (!conn) {
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtcon);
		return;
	}

	reply_outbuf(req, 2, 0);
	SSVAL(req->outbuf,smb_vwv0,xconn->smb1.negprot.max_recv);
	SSVAL(req->outbuf,smb_vwv1,conn->cnum);
	SSVAL(req->outbuf,smb_tid,conn->cnum);

	DEBUG(3,("tcon service=%s cnum=%d\n",
		 service, conn->cnum));

	END_PROFILE(SMBtcon);
	return;
}

/****************************************************************************
 Reply to a tcon and X.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tcon_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	const char *service = NULL;
	TALLOC_CTX *ctx = talloc_tos();
	/* what the cleint thinks the device is */
	char *client_devicetype = NULL;
	/* what the server tells the client the share represents */
	const char *server_devicetype;
	NTSTATUS nt_status;
	int passlen;
	char *path = NULL;
	const uint8_t *p;
	const char *q;
	uint16_t tcon_flags;
	struct smbXsrv_session *session = NULL;
	NTTIME now = timeval_to_nttime(&req->request_time);
	bool session_key_updated = false;
	uint16_t optional_support = 0;
	struct smbXsrv_connection *xconn = req->xconn;

	START_PROFILE(SMBtconX);

	if (req->wct < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	passlen = SVAL(req->vwv+3, 0);
	tcon_flags = SVAL(req->vwv+2, 0);

	/* we might have to close an old one */
	if ((tcon_flags & TCONX_FLAG_DISCONNECT_TID) && conn) {
		struct smbXsrv_tcon *tcon;
		NTSTATUS status;

		tcon = conn->tcon;
		req->conn = NULL;
		conn = NULL;

		/*
		 * TODO: cancel all outstanding requests on the tcon
		 */
		status = smbXsrv_tcon_disconnect(tcon, req->vuid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("reply_tcon_and_X: "
				  "smbXsrv_tcon_disconnect() failed: %s\n",
				  nt_errstr(status)));
			/*
			 * If we hit this case, there is something completely
			 * wrong, so we better disconnect the transport connection.
			 */
			END_PROFILE(SMBtconX);
			exit_server(__location__ ": smbXsrv_tcon_disconnect failed");
			return;
		}

		TALLOC_FREE(tcon);
	}

	if ((passlen > MAX_PASS_LEN) || (passlen >= req->buflen)) {
		reply_force_doserror(req, ERRDOS, ERRbuftoosmall);
		END_PROFILE(SMBtconX);
		return;
	}

	if (xconn->smb1.negprot.encrypted_passwords) {
		p = req->buf + passlen;
	} else {
		p = req->buf + passlen + 1;
	}

	p += srvstr_pull_req_talloc(ctx, req, &path, p, STR_TERMINATE);

	if (path == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	/*
	 * the service name can be either: \\server\share
	 * or share directly like on the DELL PowerVault 705
	 */
	if (*path=='\\') {
		q = strchr_m(path+2,'\\');
		if (!q) {
			reply_nterror(req, NT_STATUS_BAD_NETWORK_NAME);
			END_PROFILE(SMBtconX);
			return;
		}
		service = q+1;
	} else {
		service = path;
	}

	p += srvstr_pull_talloc(ctx, req->inbuf, req->flags2,
				&client_devicetype, p,
				MIN(6, smbreq_bufrem(req, p)), STR_ASCII);

	if (client_devicetype == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	DEBUG(4,("Client requested device type [%s] for share [%s]\n", client_devicetype, service));

	nt_status = smb1srv_session_lookup(xconn,
					   req->vuid, now, &session);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_USER_SESSION_DELETED)) {
		reply_force_doserror(req, ERRSRV, ERRbaduid);
		END_PROFILE(SMBtconX);
		return;
	}
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtconX);
		return;
	}
	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		END_PROFILE(SMBtconX);
		return;
	}

	if (session->global->auth_session_info == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		END_PROFILE(SMBtconX);
		return;
	}

	/*
	 * If there is no application key defined yet
	 * we create one.
	 *
	 * This means we setup the application key on the
	 * first tcon that happens via the given session.
	 *
	 * Once the application key is defined, it does not
	 * change any more.
	 */
	if (session->global->application_key.length == 0 &&
	    session->global->signing_key.length > 0)
	{
		struct smbXsrv_session *x = session;
		struct auth_session_info *session_info =
			session->global->auth_session_info;
		uint8_t session_key[16];

		ZERO_STRUCT(session_key);
		memcpy(session_key, x->global->signing_key.data,
		       MIN(x->global->signing_key.length, sizeof(session_key)));

		/*
		 * The application key is truncated/padded to 16 bytes
		 */
		x->global->application_key = data_blob_talloc(x->global,
							     session_key,
							     sizeof(session_key));
		ZERO_STRUCT(session_key);
		if (x->global->application_key.data == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}

		if (tcon_flags & TCONX_FLAG_EXTENDED_SIGNATURES) {
			smb_key_derivation(x->global->application_key.data,
					   x->global->application_key.length,
					   x->global->application_key.data);
			optional_support |= SMB_EXTENDED_SIGNATURES;
		}

		/*
		 * Place the application key into the session_info
		 */
		data_blob_clear_free(&session_info->session_key);
		session_info->session_key = data_blob_dup_talloc(session_info,
						x->global->application_key);
		if (session_info->session_key.data == NULL) {
			data_blob_clear_free(&x->global->application_key);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}
		session_key_updated = true;
	}

	conn = make_connection(req, now, service, client_devicetype,
			       req->vuid, &nt_status);
	req->conn =conn;

	if (!conn) {
		if (session_key_updated) {
			struct smbXsrv_session *x = session;
			struct auth_session_info *session_info =
				session->global->auth_session_info;
			data_blob_clear_free(&x->global->application_key);
			data_blob_clear_free(&session_info->session_key);
		}
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtconX);
		return;
	}

	if ( IS_IPC(conn) )
		server_devicetype = "IPC";
	else if ( IS_PRINT(conn) )
		server_devicetype = "LPT1:";
	else
		server_devicetype = "A:";

	if (get_Protocol() < PROTOCOL_NT1) {
		reply_outbuf(req, 2, 0);
		if (message_push_string(&req->outbuf, server_devicetype,
					STR_TERMINATE|STR_ASCII) == -1) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}
	} else {
		/* NT sets the fstype of IPC$ to the null string */
		const char *fstype = IS_IPC(conn) ? "" : lp_fstype(SNUM(conn));

		if (tcon_flags & TCONX_FLAG_EXTENDED_RESPONSE) {
			/* Return permissions. */
			uint32_t perm1 = 0;
			uint32_t perm2 = 0;

			reply_outbuf(req, 7, 0);

			if (IS_IPC(conn)) {
				perm1 = FILE_ALL_ACCESS;
				perm2 = FILE_ALL_ACCESS;
			} else {
				perm1 = conn->share_access;
			}

			SIVAL(req->outbuf, smb_vwv3, perm1);
			SIVAL(req->outbuf, smb_vwv5, perm2);
		} else {
			reply_outbuf(req, 3, 0);
		}

		if ((message_push_string(&req->outbuf, server_devicetype,
					 STR_TERMINATE|STR_ASCII) == -1)
		    || (message_push_string(&req->outbuf, fstype,
					    STR_TERMINATE) == -1)) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}

		/* what does setting this bit do? It is set by NT4 and
		   may affect the ability to autorun mounted cdroms */
		optional_support |= SMB_SUPPORT_SEARCH_BITS;
		optional_support |=
			(lp_csc_policy(SNUM(conn)) << SMB_CSC_POLICY_SHIFT);

		if (lp_msdfs_root(SNUM(conn)) && lp_host_msdfs()) {
			DEBUG(2,("Serving %s as a Dfs root\n",
				 lp_servicename(ctx, SNUM(conn)) ));
			optional_support |= SMB_SHARE_IN_DFS;
		}

		SSVAL(req->outbuf, smb_vwv2, optional_support);
	}

	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	DEBUG(3,("tconX service=%s \n",
		 service));

	/* set the incoming and outgoing tid to the just created one */
	SSVAL(discard_const_p(uint8_t, req->inbuf),smb_tid,conn->cnum);
	SSVAL(req->outbuf,smb_tid,conn->cnum);

	END_PROFILE(SMBtconX);

	req->tid = conn->cnum;
}

/****************************************************************************
 Reply to an unknown type.
****************************************************************************/

void reply_unknown_new(struct smb_request *req, uint8_t type)
{
	DEBUG(0, ("unknown command type (%s): type=%d (0x%X)\n",
		  smb_fn_name(type), type, type));
	reply_force_doserror(req, ERRSRV, ERRunknownsmb);
	return;
}

/****************************************************************************
 Reply to an ioctl.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_ioctl(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint16_t device;
	uint16_t function;
	uint32_t ioctl_code;
	int replysize;
	char *p;

	START_PROFILE(SMBioctl);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBioctl);
		return;
	}

	device     = SVAL(req->vwv+1, 0);
	function   = SVAL(req->vwv+2, 0);
	ioctl_code = (device << 16) + function;

	DEBUG(4, ("Received IOCTL (code 0x%x)\n", ioctl_code));

	switch (ioctl_code) {
	    case IOCTL_QUERY_JOB_INFO:
		    replysize = 32;
		    break;
	    default:
		    reply_force_doserror(req, ERRSRV, ERRnosupport);
		    END_PROFILE(SMBioctl);
		    return;
	}

	reply_outbuf(req, 8, replysize+1);
	SSVAL(req->outbuf,smb_vwv1,replysize); /* Total data bytes returned */
	SSVAL(req->outbuf,smb_vwv5,replysize); /* Data bytes this buffer */
	SSVAL(req->outbuf,smb_vwv6,52);        /* Offset to data */
	p = smb_buf(req->outbuf);
	memset(p, '\0', replysize+1); /* valgrind-safe. */
	p += 1;          /* Allow for alignment */

	switch (ioctl_code) {
		case IOCTL_QUERY_JOB_INFO:		    
		{
			NTSTATUS status;
			size_t len = 0;
			files_struct *fsp = file_fsp(
				req, SVAL(req->vwv+0, 0));
			if (!fsp) {
				reply_nterror(req, NT_STATUS_INVALID_HANDLE);
				END_PROFILE(SMBioctl);
				return;
			}
			/* Job number */
			SSVAL(p, 0, print_spool_rap_jobid(fsp->print_file));

			status = srvstr_push((char *)req->outbuf, req->flags2, p+2,
				    lp_netbios_name(), 15,
				    STR_TERMINATE|STR_ASCII, &len);
			if (!NT_STATUS_IS_OK(status)) {
				reply_nterror(req, status);
				END_PROFILE(SMBioctl);
				return;
			}
			if (conn) {
				status = srvstr_push((char *)req->outbuf, req->flags2,
					    p+18,
					    lp_servicename(talloc_tos(),
							   SNUM(conn)),
					    13, STR_TERMINATE|STR_ASCII, &len);
				if (!NT_STATUS_IS_OK(status)) {
					reply_nterror(req, status);
					END_PROFILE(SMBioctl);
					return;
				}
			} else {
				memset(p+18, 0, 13);
			}
			break;
		}
	}

	END_PROFILE(SMBioctl);
	return;
}

/****************************************************************************
 Strange checkpath NTSTATUS mapping.
****************************************************************************/

static NTSTATUS map_checkpath_error(uint16_t flags2, NTSTATUS status)
{
	/* Strange DOS error code semantics only for checkpath... */
	if (!(flags2 & FLAGS2_32_BIT_ERROR_CODES)) {
		if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_INVALID,status)) {
			/* We need to map to ERRbadpath */
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
	}
	return status;
}

/****************************************************************************
 Reply to a checkpath.
****************************************************************************/

void reply_checkpath(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *name = NULL;
	NTSTATUS status;
	uint32_t ucf_flags = (req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcheckpath);

	srvstr_get_path_req(ctx, req, &name, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);

	if (!NT_STATUS_IS_OK(status)) {
		status = map_checkpath_error(req->flags2, status);
		reply_nterror(req, status);
		END_PROFILE(SMBcheckpath);
		return;
	}

	DEBUG(3,("reply_checkpath %s mode=%d\n", name, (int)SVAL(req->vwv+0, 0)));

	status = filename_convert(ctx,
				conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				name,
				ucf_flags,
				NULL,
				&smb_fname);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBcheckpath);
			return;
		}
		goto path_err;
	}

	if (!VALID_STAT(smb_fname->st) &&
	    (SMB_VFS_STAT(conn, smb_fname) != 0)) {
		DEBUG(3,("reply_checkpath: stat of %s failed (%s)\n",
			smb_fname_str_dbg(smb_fname), strerror(errno)));
		status = map_nt_error_from_unix(errno);
		goto path_err;
	}

	if (!S_ISDIR(smb_fname->st.st_ex_mode)) {
		reply_botherror(req, NT_STATUS_NOT_A_DIRECTORY,
				ERRDOS, ERRbadpath);
		goto out;
	}

	reply_outbuf(req, 0, 0);

 path_err:
	/* We special case this - as when a Windows machine
		is parsing a path is steps through the components
		one at a time - if a component fails it expects
		ERRbadpath, not ERRbadfile.
	*/
	status = map_checkpath_error(req->flags2, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * Windows returns different error codes if
		 * the parent directory is valid but not the
		 * last component - it returns NT_STATUS_OBJECT_NAME_NOT_FOUND
		 * for that case and NT_STATUS_OBJECT_PATH_NOT_FOUND
		 * if the path is invalid.
		 */
		reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ERRDOS, ERRbadpath);
		goto out;
	}

	reply_nterror(req, status);

 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBcheckpath);
	return;
}

/****************************************************************************
 Reply to a getatr.
****************************************************************************/

void reply_getatr(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	int mode=0;
	off_t size=0;
	time_t mtime=0;
	const char *p;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();
	bool ask_sharemode = lp_parm_bool(SNUM(conn), "smbd", "search ask sharemode", true);

	START_PROFILE(SMBgetatr);

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &fname, p, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	/* dos smetimes asks for a stat of "" - it returns a "hidden directory"
		under WfWg - weird! */
	if (*fname == '\0') {
		mode = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY;
		if (!CAN_WRITE(conn)) {
			mode |= FILE_ATTRIBUTE_READONLY;
		}
		size = 0;
		mtime = 0;
	} else {
		uint32_t ucf_flags = (req->posix_pathnames ?
				UCF_POSIX_PATHNAMES : 0);
		status = filename_convert(ctx,
				conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				ucf_flags,
				NULL,
				&smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
				reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
						ERRSRV, ERRbadpath);
				goto out;
			}
			reply_nterror(req, status);
			goto out;
		}
		if (!VALID_STAT(smb_fname->st) &&
		    (SMB_VFS_STAT(conn, smb_fname) != 0)) {
			DEBUG(3,("reply_getatr: stat of %s failed (%s)\n",
				 smb_fname_str_dbg(smb_fname),
				 strerror(errno)));
			reply_nterror(req,  map_nt_error_from_unix(errno));
			goto out;
		}

		mode = dos_mode(conn, smb_fname);
		size = smb_fname->st.st_ex_size;

		if (ask_sharemode) {
			struct timespec write_time_ts;
			struct file_id fileid;

			ZERO_STRUCT(write_time_ts);
			fileid = vfs_file_id_from_sbuf(conn, &smb_fname->st);
			get_file_infos(fileid, 0, NULL, &write_time_ts);
			if (!null_timespec(write_time_ts)) {
				update_stat_ex_mtime(&smb_fname->st, write_time_ts);
			}
		}

		mtime = convert_timespec_to_time_t(smb_fname->st.st_ex_mtime);
		if (mode & FILE_ATTRIBUTE_DIRECTORY) {
			size = 0;
		}
	}

	reply_outbuf(req, 10, 0);

	SSVAL(req->outbuf,smb_vwv0,mode);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv1,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv1,mtime);
	}
	SIVAL(req->outbuf,smb_vwv3,(uint32_t)size);

	if (get_Protocol() >= PROTOCOL_NT1) {
		SSVAL(req->outbuf, smb_flg2,
		      SVAL(req->outbuf, smb_flg2) | FLAGS2_IS_LONG_NAME);
	}

	DEBUG(3,("reply_getatr: name=%s mode=%d size=%u\n",
		 smb_fname_str_dbg(smb_fname), mode, (unsigned int)size));

 out:
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(fname);
	END_PROFILE(SMBgetatr);
	return;
}

/****************************************************************************
 Reply to a setatr.
****************************************************************************/

void reply_setatr(struct smb_request *req)
{
	struct smb_file_time ft;
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	int mode;
	time_t mtime;
	const char *p;
	NTSTATUS status;
	uint32_t ucf_flags = (req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBsetatr);

	ZERO_STRUCT(ft);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &fname, p, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert(ctx,
				conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				ucf_flags,
				NULL,
				&smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (smb_fname->base_name[0] == '.' &&
	    smb_fname->base_name[1] == '\0') {
		/*
		 * Not sure here is the right place to catch this
		 * condition. Might be moved to somewhere else later -- vl
		 */
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	mode = SVAL(req->vwv+0, 0);
	mtime = srv_make_unix_date3(req->vwv+1);

	if (mode != FILE_ATTRIBUTE_NORMAL) {
		if (VALID_STAT_OF_DIR(smb_fname->st))
			mode |= FILE_ATTRIBUTE_DIRECTORY;
		else
			mode &= ~FILE_ATTRIBUTE_DIRECTORY;

		status = check_access(conn, NULL, smb_fname,
					FILE_WRITE_ATTRIBUTES);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}

		if (file_set_dosmode(conn, smb_fname, mode, NULL,
				     false) != 0) {
			reply_nterror(req, map_nt_error_from_unix(errno));
			goto out;
		}
	}

	ft.mtime = convert_time_t_to_timespec(mtime);
	status = smb_set_file_time(conn, NULL, smb_fname, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	reply_outbuf(req, 0, 0);

	DEBUG(3, ("setatr name=%s mode=%d\n", smb_fname_str_dbg(smb_fname),
		 mode));
 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBsetatr);
	return;
}

/****************************************************************************
 Reply to a dskattr.
****************************************************************************/

void reply_dskattr(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint64_t ret;
	uint64_t dfree,dsize,bsize;
	struct smb_filename smb_fname;
	START_PROFILE(SMBdskattr);

	ZERO_STRUCT(smb_fname);
	smb_fname.base_name = discard_const_p(char, ".");

	if (SMB_VFS_STAT(conn, &smb_fname) != 0) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		DBG_WARNING("stat of . failed (%s)\n", strerror(errno));
		END_PROFILE(SMBdskattr);
		return;
	}

	ret = get_dfree_info(conn, &smb_fname, &bsize, &dfree, &dsize);
	if (ret == (uint64_t)-1) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		END_PROFILE(SMBdskattr);
		return;
	}

	/*
	 * Force max to fit in 16 bit fields.
	 */
	while (dfree > WORDMAX || dsize > WORDMAX || bsize < 512) {
		dfree /= 2;
		dsize /= 2;
		bsize *= 2;
		if (bsize > (WORDMAX*512)) {
			bsize = (WORDMAX*512);
			if (dsize > WORDMAX)
				dsize = WORDMAX;
			if (dfree >  WORDMAX)
				dfree = WORDMAX;
			break;
		}
	}

	reply_outbuf(req, 5, 0);

	if (get_Protocol() <= PROTOCOL_LANMAN2) {
		double total_space, free_space;
		/* we need to scale this to a number that DOS6 can handle. We
		   use floating point so we can handle large drives on systems
		   that don't have 64 bit integers 

		   we end up displaying a maximum of 2G to DOS systems
		*/
		total_space = dsize * (double)bsize;
		free_space = dfree * (double)bsize;

		dsize = (uint64_t)((total_space+63*512) / (64*512));
		dfree = (uint64_t)((free_space+63*512) / (64*512));

		if (dsize > 0xFFFF) dsize = 0xFFFF;
		if (dfree > 0xFFFF) dfree = 0xFFFF;

		SSVAL(req->outbuf,smb_vwv0,dsize);
		SSVAL(req->outbuf,smb_vwv1,64); /* this must be 64 for dos systems */
		SSVAL(req->outbuf,smb_vwv2,512); /* and this must be 512 */
		SSVAL(req->outbuf,smb_vwv3,dfree);
	} else {
		SSVAL(req->outbuf,smb_vwv0,dsize);
		SSVAL(req->outbuf,smb_vwv1,bsize/512);
		SSVAL(req->outbuf,smb_vwv2,512);
		SSVAL(req->outbuf,smb_vwv3,dfree);
	}

	DEBUG(3,("dskattr dfree=%d\n", (unsigned int)dfree));

	END_PROFILE(SMBdskattr);
	return;
}

/*
 * Utility function to split the filename from the directory.
 */
static NTSTATUS split_fname_dir_mask(TALLOC_CTX *ctx, const char *fname_in,
				     char **fname_dir_out,
				     char **fname_mask_out)
{
	const char *p = NULL;
	char *fname_dir = NULL;
	char *fname_mask = NULL;

	p = strrchr_m(fname_in, '/');
	if (!p) {
		fname_dir = talloc_strdup(ctx, ".");
		fname_mask = talloc_strdup(ctx, fname_in);
	} else {
		fname_dir = talloc_strndup(ctx, fname_in,
		    PTR_DIFF(p, fname_in));
		fname_mask = talloc_strdup(ctx, p+1);
	}

	if (!fname_dir || !fname_mask) {
		TALLOC_FREE(fname_dir);
		TALLOC_FREE(fname_mask);
		return NT_STATUS_NO_MEMORY;
	}

	*fname_dir_out = fname_dir;
	*fname_mask_out = fname_mask;
	return NT_STATUS_OK;
}

/****************************************************************************
 Make a dir struct.
****************************************************************************/

static bool make_dir_struct(TALLOC_CTX *ctx,
			    char *buf,
			    const char *mask,
			    const char *fname,
			    off_t size,
			    uint32_t mode,
			    time_t date,
			    bool uc)
{
	char *p;
	char *mask2 = talloc_strdup(ctx, mask);

	if (!mask2) {
		return False;
	}

	if ((mode & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		size = 0;
	}

	memset(buf+1,' ',11);
	if ((p = strchr_m(mask2,'.')) != NULL) {
		*p = 0;
		push_ascii(buf+1,mask2,8, 0);
		push_ascii(buf+9,p+1,3, 0);
		*p = '.';
	} else {
		push_ascii(buf+1,mask2,11, 0);
	}

	memset(buf+21,'\0',DIR_STRUCT_SIZE-21);
	SCVAL(buf,21,mode);
	srv_put_dos_date(buf,22,date);
	SSVAL(buf,26,size & 0xFFFF);
	SSVAL(buf,28,(size >> 16)&0xFFFF);
	/* We only uppercase if FLAGS2_LONG_PATH_COMPONENTS is zero in the input buf.
	   Strange, but verified on W2K3. Needed for OS/2. JRA. */
	push_ascii(buf+30,fname,12, uc ? STR_UPPER : 0);
	DEBUG(8,("put name [%s] from [%s] into dir struct\n",buf+30, fname));
	return True;
}

/****************************************************************************
 Reply to a search.
 Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/

void reply_search(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *path = NULL;
	char *mask = NULL;
	char *directory = NULL;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	off_t size;
	uint32_t mode;
	struct timespec date;
	uint32_t dirtype;
	unsigned int numentries = 0;
	unsigned int maxentries = 0;
	bool finished = False;
	const char *p;
	int status_len;
	char status[21];
	int dptr_num= -1;
	bool check_descend = False;
	bool expect_close = False;
	NTSTATUS nt_status;
	bool mask_contains_wcard = False;
	bool allow_long_path_components = (req->flags2 & FLAGS2_LONG_PATH_COMPONENTS) ? True : False;
	TALLOC_CTX *ctx = talloc_tos();
	bool ask_sharemode = lp_parm_bool(SNUM(conn), "smbd", "search ask sharemode", true);
	struct dptr_struct *dirptr = NULL;
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;

	START_PROFILE(SMBsearch);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	if (req->posix_pathnames) {
		reply_unknown_new(req, req->cmd);
		goto out;
	}

	/* If we were called as SMBffirst then we must expect close. */
	if(req->cmd == SMBffirst) {
		expect_close = True;
	}

	reply_outbuf(req, 1, 3);
	maxentries = SVAL(req->vwv+0, 0);
	dirtype = SVAL(req->vwv+1, 0);
	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req_wcard(ctx, req, &path, p, STR_TERMINATE,
				       &nt_status, &mask_contains_wcard);
	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, nt_status);
		goto out;
	}

	p++;
	status_len = SVAL(p, 0);
	p += 2;

	/* dirtype &= ~FILE_ATTRIBUTE_DIRECTORY; */

	if (status_len == 0) {
		struct smb_filename *smb_dname = NULL;
		uint32_t ucf_flags = UCF_ALWAYS_ALLOW_WCARD_LCOMP |
			(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
		nt_status = filename_convert(ctx, conn,
					     req->flags2 & FLAGS2_DFS_PATHNAMES,
					     path,
					     ucf_flags,
					     &mask_contains_wcard,
					     &smb_fname);
		if (!NT_STATUS_IS_OK(nt_status)) {
			if (NT_STATUS_EQUAL(nt_status,NT_STATUS_PATH_NOT_COVERED)) {
				reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
						ERRSRV, ERRbadpath);
				goto out;
			}
			reply_nterror(req, nt_status);
			goto out;
		}

		directory = smb_fname->base_name;

		p = strrchr_m(directory,'/');
		if ((p != NULL) && (*directory != '/')) {
			mask = talloc_strdup(ctx, p + 1);
			directory = talloc_strndup(ctx, directory,
						   PTR_DIFF(p, directory));
		} else {
			mask = talloc_strdup(ctx, directory);
			directory = talloc_strdup(ctx,".");
		}

		if (!directory) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		memset((char *)status,'\0',21);
		SCVAL(status,0,(dirtype & 0x1F));

		smb_dname = synthetic_smb_fname(talloc_tos(),
					directory,
					NULL,
					NULL,
					smb_fname->flags);
		if (smb_dname == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		nt_status = dptr_create(conn,
					NULL, /* req */
					NULL, /* fsp */
					smb_dname,
					True,
					expect_close,
					req->smbpid,
					mask,
					mask_contains_wcard,
					dirtype,
					&dirptr);

		TALLOC_FREE(smb_dname);

		if (!NT_STATUS_IS_OK(nt_status)) {
			reply_nterror(req, nt_status);
			goto out;
		}
		dptr_num = dptr_dnum(dirptr);
	} else {
		int status_dirtype;
		const char *dirpath;

		memcpy(status,p,21);
		status_dirtype = CVAL(status,0) & 0x1F;
		if (status_dirtype != (dirtype & 0x1F)) {
			dirtype = status_dirtype;
		}

		dirptr = dptr_fetch(sconn, status+12,&dptr_num);
		if (!dirptr) {
			goto SearchEmpty;
		}
		dirpath = dptr_path(sconn, dptr_num);
		directory = talloc_strdup(ctx, dirpath);
		if (!directory) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		mask = talloc_strdup(ctx, dptr_wcard(sconn, dptr_num));
		if (!mask) {
			goto SearchEmpty;
		}
		/*
		 * For a 'continue' search we have no string. So
		 * check from the initial saved string.
		 */
		if (!req->posix_pathnames) {
			mask_contains_wcard = ms_has_wild(mask);
		}
		dirtype = dptr_attr(sconn, dptr_num);
	}

	DEBUG(4,("dptr_num is %d\n",dptr_num));

	/* Initialize per SMBsearch/SMBffirst/SMBfunique operation data */
	dptr_init_search_op(dirptr);

	if ((dirtype&0x1F) == FILE_ATTRIBUTE_VOLUME) {
		char buf[DIR_STRUCT_SIZE];
		memcpy(buf,status,21);
		if (!make_dir_struct(ctx,buf,"???????????",volume_label(ctx, SNUM(conn)),
				0,FILE_ATTRIBUTE_VOLUME,0,!allow_long_path_components)) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}
		dptr_fill(sconn, buf+12,dptr_num);
		if (dptr_zero(buf+12) && (status_len==0)) {
			numentries = 1;
		} else {
			numentries = 0;
		}
		if (message_push_blob(&req->outbuf,
				      data_blob_const(buf, sizeof(buf)))
		    == -1) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}
	} else {
		unsigned int i;
		size_t hdr_size = ((uint8_t *)smb_buf(req->outbuf) + 3 - req->outbuf);
		size_t available_space = xconn->smb1.sessions.max_send - hdr_size;

		maxentries = MIN(maxentries, available_space/DIR_STRUCT_SIZE);

		DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
			 directory,lp_dont_descend(ctx, SNUM(conn))));
		if (in_list(directory, lp_dont_descend(ctx, SNUM(conn)),True)) {
			check_descend = True;
		}

		for (i=numentries;(i<maxentries) && !finished;i++) {
			finished = !get_dir_entry(ctx,
						  dirptr,
						  mask,
						  dirtype,
						  &fname,
						  &size,
						  &mode,
						  &date,
						  check_descend,
						  ask_sharemode);
			if (!finished) {
				char buf[DIR_STRUCT_SIZE];
				memcpy(buf,status,21);
				if (!make_dir_struct(ctx,
						buf,
						mask,
						fname,
						size,
						mode,
						convert_timespec_to_time_t(date),
						!allow_long_path_components)) {
					reply_nterror(req, NT_STATUS_NO_MEMORY);
					goto out;
				}
				if (!dptr_fill(sconn, buf+12,dptr_num)) {
					break;
				}
				if (message_push_blob(&req->outbuf,
						      data_blob_const(buf, sizeof(buf)))
				    == -1) {
					reply_nterror(req, NT_STATUS_NO_MEMORY);
					goto out;
				}
				numentries++;
			}
		}
	}

  SearchEmpty:

	/* If we were called as SMBffirst with smb_search_id == NULL
		and no entries were found then return error and close dirptr 
		(X/Open spec) */

	if (numentries == 0) {
		dptr_close(sconn, &dptr_num);
	} else if(expect_close && status_len == 0) {
		/* Close the dptr - we know it's gone */
		dptr_close(sconn, &dptr_num);
	}

	/* If we were called as SMBfunique, then we can close the dirptr now ! */
	if(dptr_num >= 0 && req->cmd == SMBfunique) {
		dptr_close(sconn, &dptr_num);
	}

	if ((numentries == 0) && !mask_contains_wcard) {
		reply_botherror(req, STATUS_NO_MORE_FILES, ERRDOS, ERRnofiles);
		goto out;
	}

	SSVAL(req->outbuf,smb_vwv0,numentries);
	SSVAL(req->outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
	SCVAL(smb_buf(req->outbuf),0,5);
	SSVAL(smb_buf(req->outbuf),1,numentries*DIR_STRUCT_SIZE);

	/* The replies here are never long name. */
	SSVAL(req->outbuf, smb_flg2,
	      SVAL(req->outbuf, smb_flg2) & (~FLAGS2_IS_LONG_NAME));
	if (!allow_long_path_components) {
		SSVAL(req->outbuf, smb_flg2,
		      SVAL(req->outbuf, smb_flg2)
		      & (~FLAGS2_LONG_PATH_COMPONENTS));
	}

	/* This SMB *always* returns ASCII names. Remove the unicode bit in flags2. */
	SSVAL(req->outbuf, smb_flg2,
	      (SVAL(req->outbuf, smb_flg2) & (~FLAGS2_UNICODE_STRINGS)));

	DEBUG(4,("%s mask=%s path=%s dtype=%d nument=%u of %u\n",
		smb_fn_name(req->cmd),
		mask,
		directory,
		dirtype,
		numentries,
		maxentries ));
 out:
	TALLOC_FREE(directory);
	TALLOC_FREE(mask);
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBsearch);
	return;
}

/****************************************************************************
 Reply to a fclose (stop directory search).
****************************************************************************/

void reply_fclose(struct smb_request *req)
{
	int status_len;
	char status[21];
	int dptr_num= -2;
	const char *p;
	char *path = NULL;
	NTSTATUS err;
	bool path_contains_wcard = False;
	TALLOC_CTX *ctx = talloc_tos();
	struct smbd_server_connection *sconn = req->sconn;

	START_PROFILE(SMBfclose);

	if (req->posix_pathnames) {
		reply_unknown_new(req, req->cmd);
		END_PROFILE(SMBfclose);
		return;
	}

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req_wcard(ctx, req, &path, p, STR_TERMINATE,
				       &err, &path_contains_wcard);
	if (!NT_STATUS_IS_OK(err)) {
		reply_nterror(req, err);
		END_PROFILE(SMBfclose);
		return;
	}
	p++;
	status_len = SVAL(p,0);
	p += 2;

	if (status_len == 0) {
		reply_force_doserror(req, ERRSRV, ERRsrverror);
		END_PROFILE(SMBfclose);
		return;
	}

	memcpy(status,p,21);

	if(dptr_fetch(sconn, status+12,&dptr_num)) {
		/*  Close the dptr - we know it's gone */
		dptr_close(sconn, &dptr_num);
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,0);

	DEBUG(3,("search close\n"));

	END_PROFILE(SMBfclose);
	return;
}

/****************************************************************************
 Reply to an open.
****************************************************************************/

void reply_open(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	uint32_t fattr=0;
	off_t size = 0;
	time_t mtime=0;
	int info;
	files_struct *fsp;
	int oplock_request;
	int deny_mode;
	uint32_t dos_attr;
	uint32_t access_mask;
	uint32_t share_mode;
	uint32_t create_disposition;
	uint32_t create_options = 0;
	uint32_t private_flags = 0;
	NTSTATUS status;
	uint32_t ucf_flags = UCF_PREP_CREATEFILE |
			(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBopen);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);
	deny_mode = SVAL(req->vwv+0, 0);
	dos_attr = SVAL(req->vwv+1, 0);

	srvstr_get_path_req(ctx, req, &fname, (const char *)req->buf+1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!map_open_params_to_ntcreate(fname, deny_mode,
					 OPENX_FILE_EXISTS_OPEN, &access_mask,
					 &share_mode, &create_disposition,
					 &create_options, &private_flags)) {
		reply_force_doserror(req, ERRDOS, ERRbadaccess);
		goto out;
	}

	status = filename_convert(ctx,
				conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				ucf_flags,
				NULL,
				&smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		0,					/* root_dir_fid */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_mode,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		dos_attr,				/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		private_flags,
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&info,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		reply_openerror(req, status);
		goto out;
	}

	/* Ensure we're pointing at the correct stat struct. */
	TALLOC_FREE(smb_fname);
	smb_fname = fsp->fsp_name;

	size = smb_fname->st.st_ex_size;
	fattr = dos_mode(conn, smb_fname);

	mtime = convert_timespec_to_time_t(smb_fname->st.st_ex_mtime);

	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		DEBUG(3,("attempt to open a directory %s\n",
			 fsp_str_dbg(fsp)));
		close_file(req, fsp, ERROR_CLOSE);
		reply_botherror(req, NT_STATUS_ACCESS_DENIED,
			ERRDOS, ERRnoaccess);
		goto out;
	}

	reply_outbuf(req, 7, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);
	SSVAL(req->outbuf,smb_vwv1,fattr);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv2,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv2,mtime);
	}
	SIVAL(req->outbuf,smb_vwv4,(uint32_t)size);
	SSVAL(req->outbuf,smb_vwv6,deny_mode);

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf,smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf,smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}
 out:
	END_PROFILE(SMBopen);
	return;
}

/****************************************************************************
 Reply to an open and X.
****************************************************************************/

void reply_open_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	uint16_t open_flags;
	int deny_mode;
	uint32_t smb_attr;
	/* Breakout the oplock request bits so we can set the
		reply bits separately. */
	int ex_oplock_request;
	int core_oplock_request;
	int oplock_request;
#if 0
	int smb_sattr = SVAL(req->vwv+4, 0);
	uint32_t smb_time = make_unix_date3(req->vwv+6);
#endif
	int smb_ofun;
	uint32_t fattr=0;
	int mtime=0;
	int smb_action = 0;
	files_struct *fsp;
	NTSTATUS status;
	uint64_t allocation_size;
	ssize_t retval = -1;
	uint32_t access_mask;
	uint32_t share_mode;
	uint32_t create_disposition;
	uint32_t create_options = 0;
	uint32_t private_flags = 0;
	uint32_t ucf_flags = UCF_PREP_CREATEFILE |
			(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBopenX);

	if (req->wct < 15) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	open_flags = SVAL(req->vwv+2, 0);
	deny_mode = SVAL(req->vwv+3, 0);
	smb_attr = SVAL(req->vwv+5, 0);
	ex_oplock_request = EXTENDED_OPLOCK_REQUEST(req->inbuf);
	core_oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);
	oplock_request = ex_oplock_request | core_oplock_request;
	smb_ofun = SVAL(req->vwv+8, 0);
	allocation_size = (uint64_t)IVAL(req->vwv+9, 0);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support()) {
			reply_open_pipe_and_X(conn, req);
		} else {
			reply_nterror(req, NT_STATUS_NETWORK_ACCESS_DENIED);
		}
		goto out;
	}

	/* XXXX we need to handle passed times, sattr and flags */
	srvstr_get_path_req(ctx, req, &fname, (const char *)req->buf,
			STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!map_open_params_to_ntcreate(fname, deny_mode,
					 smb_ofun,
					 &access_mask, &share_mode,
					 &create_disposition,
					 &create_options,
					 &private_flags)) {
		reply_force_doserror(req, ERRDOS, ERRbadaccess);
		goto out;
	}

	status = filename_convert(ctx,
				conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				ucf_flags,
				NULL,
				&smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		0,					/* root_dir_fid */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_mode,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		smb_attr,				/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		private_flags,
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&smb_action,				/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		reply_openerror(req, status);
		goto out;
	}

	/* Setting the "size" field in vwv9 and vwv10 causes the file to be set to this size,
	   if the file is truncated or created. */
	if (((smb_action == FILE_WAS_CREATED) || (smb_action == FILE_WAS_OVERWRITTEN)) && allocation_size) {
		fsp->initial_allocation_size = smb_roundup(fsp->conn, allocation_size);
		if (vfs_allocate_file_space(fsp, fsp->initial_allocation_size) == -1) {
			close_file(req, fsp, ERROR_CLOSE);
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto out;
		}
		retval = vfs_set_filelen(fsp, (off_t)allocation_size);
		if (retval < 0) {
			close_file(req, fsp, ERROR_CLOSE);
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto out;
		}
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			close_file(req, fsp, ERROR_CLOSE);
			reply_nterror(req, status);
			goto out;
		}
	}

	fattr = dos_mode(conn, fsp->fsp_name);
	mtime = convert_timespec_to_time_t(fsp->fsp_name->st.st_ex_mtime);
	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		close_file(req, fsp, ERROR_CLOSE);
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	/* If the caller set the extended oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for extended oplock reply.
	*/

	if (ex_oplock_request && lp_fake_oplocks(SNUM(conn))) {
		smb_action |= EXTENDED_OPLOCK_GRANTED;
	}

	if(ex_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		smb_action |= EXTENDED_OPLOCK_GRANTED;
	}

	/* If the caller set the core oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for core oplock reply.
	*/

	if (open_flags & EXTENDED_RESPONSE_REQUIRED) {
		reply_outbuf(req, 19, 0);
	} else {
		reply_outbuf(req, 15, 0);
	}

	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	if (core_oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(core_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	SSVAL(req->outbuf,smb_vwv2,fsp->fnum);
	SSVAL(req->outbuf,smb_vwv3,fattr);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv4,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv4,mtime);
	}
	SIVAL(req->outbuf,smb_vwv6,(uint32_t)fsp->fsp_name->st.st_ex_size);
	SSVAL(req->outbuf,smb_vwv8,GET_OPENX_MODE(deny_mode));
	SSVAL(req->outbuf,smb_vwv11,smb_action);

	if (open_flags & EXTENDED_RESPONSE_REQUIRED) {
		SIVAL(req->outbuf, smb_vwv15, SEC_STD_ALL);
	}

 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBopenX);
	return;
}

/****************************************************************************
 Reply to a SMBulogoffX.
****************************************************************************/

void reply_ulogoffX(struct smb_request *req)
{
	struct smbd_server_connection *sconn = req->sconn;
	struct user_struct *vuser;
	struct smbXsrv_session *session = NULL;
	NTSTATUS status;

	START_PROFILE(SMBulogoffX);

	vuser = get_valid_user_struct(sconn, req->vuid);

	if(vuser == NULL) {
		DEBUG(3,("ulogoff, vuser id %llu does not map to user.\n",
			 (unsigned long long)req->vuid));

		req->vuid = UID_FIELD_INVALID;
		reply_force_doserror(req, ERRSRV, ERRbaduid);
		END_PROFILE(SMBulogoffX);
		return;
	}

	session = vuser->session;
	vuser = NULL;

	/*
	 * TODO: cancel all outstanding requests on the session
	 */
	status = smbXsrv_session_logoff(session);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("reply_ulogoff: "
			  "smbXsrv_session_logoff() failed: %s\n",
			  nt_errstr(status)));
		/*
		 * If we hit this case, there is something completely
		 * wrong, so we better disconnect the transport connection.
		 */
		END_PROFILE(SMBulogoffX);
		exit_server(__location__ ": smbXsrv_session_logoff failed");
		return;
	}

	TALLOC_FREE(session);

	reply_outbuf(req, 2, 0);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	DEBUG(3, ("ulogoffX vuid=%llu\n",
		  (unsigned long long)req->vuid));

	END_PROFILE(SMBulogoffX);
	req->vuid = UID_FIELD_INVALID;
}

/****************************************************************************
 Reply to a mknew or a create.
****************************************************************************/

void reply_mknew(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	uint32_t fattr = 0;
	struct smb_file_time ft;
	files_struct *fsp;
	int oplock_request = 0;
	NTSTATUS status;
	uint32_t access_mask = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
	uint32_t share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;
	uint32_t create_disposition;
	uint32_t create_options = 0;
	uint32_t ucf_flags = UCF_PREP_CREATEFILE |
			(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcreate);
	ZERO_STRUCT(ft);

        if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	fattr = SVAL(req->vwv+0, 0);
	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);

	/* mtime. */
	ft.mtime = convert_time_t_to_timespec(srv_make_unix_date3(req->vwv+1));

	srvstr_get_path_req(ctx, req, &fname, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert(ctx,
				conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				ucf_flags,
				NULL,
				&smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (fattr & FILE_ATTRIBUTE_VOLUME) {
		DEBUG(0,("Attempt to create file (%s) with volid set - "
			 "please report this\n",
			 smb_fname_str_dbg(smb_fname)));
	}

	if(req->cmd == SMBmknew) {
		/* We should fail if file exists. */
		create_disposition = FILE_CREATE;
	} else {
		/* Create if file doesn't exist, truncate if it does. */
		create_disposition = FILE_OVERWRITE_IF;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		0,					/* root_dir_fid */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_mode,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		fattr,					/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		reply_openerror(req, status);
		goto out;
	}

	ft.atime = smb_fname->st.st_ex_atime; /* atime. */
	status = smb_set_file_time(conn, fsp, smb_fname, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBcreate);
		goto out;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf,smb_flg,
				CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf,smb_flg,
				CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	DEBUG(2, ("reply_mknew: file %s\n", smb_fname_str_dbg(smb_fname)));
	DEBUG(3, ("reply_mknew %s fd=%d dmode=0x%x\n",
		  smb_fname_str_dbg(smb_fname), fsp->fh->fd,
		  (unsigned int)fattr));

 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBcreate);
	return;
}

/****************************************************************************
 Reply to a create temporary file.
****************************************************************************/

void reply_ctemp(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *wire_name = NULL;
	char *fname = NULL;
	uint32_t fattr;
	files_struct *fsp;
	int oplock_request;
	char *s;
	NTSTATUS status;
	int i;
	uint32_t ucf_flags = UCF_PREP_CREATEFILE |
			(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBctemp);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	fattr = SVAL(req->vwv+0, 0);
	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);

	srvstr_get_path_req(ctx, req, &wire_name, (const char *)req->buf+1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	for (i = 0; i < 10; i++) {
		if (*wire_name) {
			fname = talloc_asprintf(ctx,
					"%s/TMP%s",
					wire_name,
					generate_random_str_list(ctx, 5, "0123456789"));
		} else {
			fname = talloc_asprintf(ctx,
					"TMP%s",
					generate_random_str_list(ctx, 5, "0123456789"));
		}

		if (!fname) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		status = filename_convert(ctx, conn,
				req->flags2 & FLAGS2_DFS_PATHNAMES,
				fname,
				ucf_flags,
				NULL,
				&smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
				reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
				goto out;
			}
			reply_nterror(req, status);
			goto out;
		}

		/* Create the file. */
		status = SMB_VFS_CREATE_FILE(
			conn,					/* conn */
			req,					/* req */
			0,					/* root_dir_fid */
			smb_fname,				/* fname */
			FILE_GENERIC_READ | FILE_GENERIC_WRITE, /* access_mask */
			FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
			FILE_CREATE,				/* create_disposition*/
			0,					/* create_options */
			fattr,					/* file_attributes */
			oplock_request,				/* oplock_request */
			NULL,					/* lease */
			0,					/* allocation_size */
			0,					/* private_flags */
			NULL,					/* sd */
			NULL,					/* ea_list */
			&fsp,					/* result */
			NULL,					/* pinfo */
			NULL, NULL);				/* create context */

		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			TALLOC_FREE(fname);
			TALLOC_FREE(smb_fname);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			if (open_was_deferred(req->xconn, req->mid)) {
				/* We have re-scheduled this call. */
				goto out;
			}
			reply_openerror(req, status);
			goto out;
		}

		break;
	}

	if (i == 10) {
		/* Collision after 10 times... */
		reply_nterror(req, status);
		goto out;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	/* the returned filename is relative to the directory */
	s = strrchr_m(fsp->fsp_name->base_name, '/');
	if (!s) {
		s = fsp->fsp_name->base_name;
	} else {
		s++;
	}

#if 0
	/* Tested vs W2K3 - this doesn't seem to be here - null terminated filename is the only
	   thing in the byte section. JRA */
	SSVALS(p, 0, -1); /* what is this? not in spec */
#endif
	if (message_push_string(&req->outbuf, s, STR_ASCII|STR_TERMINATE)
	    == -1) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	DEBUG(2, ("reply_ctemp: created temp file %s\n", fsp_str_dbg(fsp)));
	DEBUG(3, ("reply_ctemp %s fd=%d umode=0%o\n", fsp_str_dbg(fsp),
		    fsp->fh->fd, (unsigned int)smb_fname->st.st_ex_mode));
 out:
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(wire_name);
	END_PROFILE(SMBctemp);
	return;
}

/*******************************************************************
 Check if a user is allowed to rename a file.
********************************************************************/

static NTSTATUS can_rename(connection_struct *conn, files_struct *fsp,
			uint16_t dirtype)
{
	if (!CAN_WRITE(conn)) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	if ((dirtype & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) !=
			(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
		/* Only bother to read the DOS attribute if we might deny the
		   rename on the grounds of attribute mismatch. */
		uint32_t fmode = dos_mode(conn, fsp->fsp_name);
		if ((fmode & ~dirtype) & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
			return NT_STATUS_NO_SUCH_FILE;
		}
	}

	if (S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		if (fsp->posix_flags & FSP_POSIX_FLAGS_RENAME) {
			return NT_STATUS_OK;
		}

		/* If no pathnames are open below this
		   directory, allow the rename. */

		if (lp_strict_rename(SNUM(conn))) {
			/*
			 * Strict rename, check open file db.
			 */
			if (have_file_open_below(fsp->conn, fsp->fsp_name)) {
				return NT_STATUS_ACCESS_DENIED;
			}
		} else if (file_find_subpath(fsp)) {
			/*
			 * No strict rename, just look in local process.
			 */
			return NT_STATUS_ACCESS_DENIED;
		}
		return NT_STATUS_OK;
	}

	if (fsp->access_mask & (DELETE_ACCESS|FILE_WRITE_ATTRIBUTES)) {
		return NT_STATUS_OK;
	}

	return NT_STATUS_ACCESS_DENIED;
}

/*******************************************************************
 * unlink a file with all relevant access checks
 *******************************************************************/

static NTSTATUS do_unlink(connection_struct *conn,
			struct smb_request *req,
			struct smb_filename *smb_fname,
			uint32_t dirtype)
{
	uint32_t fattr;
	files_struct *fsp;
	uint32_t dirtype_orig = dirtype;
	NTSTATUS status;
	int ret;
	bool posix_paths = (req != NULL && req->posix_pathnames);

	DEBUG(10,("do_unlink: %s, dirtype = %d\n",
		  smb_fname_str_dbg(smb_fname),
		  dirtype));

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	if (posix_paths) {
		ret = SMB_VFS_LSTAT(conn, smb_fname);
	} else {
		ret = SMB_VFS_STAT(conn, smb_fname);
	}
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	fattr = dos_mode(conn, smb_fname);

	if (dirtype & FILE_ATTRIBUTE_NORMAL) {
		dirtype = FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY;
	}

	dirtype &= (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
	if (!dirtype) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	if (!dir_check_ftype(fattr, dirtype)) {
		if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
		return NT_STATUS_NO_SUCH_FILE;
	}

	if (dirtype_orig & 0x8000) {
		/* These will never be set for POSIX. */
		return NT_STATUS_NO_SUCH_FILE;
	}

#if 0
	if ((fattr & dirtype) & FILE_ATTRIBUTE_DIRECTORY) {
                return NT_STATUS_FILE_IS_A_DIRECTORY;
        }

        if ((fattr & ~dirtype) & (FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)) {
                return NT_STATUS_NO_SUCH_FILE;
        }

	if (dirtype & 0xFF00) {
		/* These will never be set for POSIX. */
		return NT_STATUS_NO_SUCH_FILE;
	}

	dirtype &= 0xFF;
	if (!dirtype) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	/* Can't delete a directory. */
	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}
#endif

#if 0 /* JRATEST */
	else if (dirtype & FILE_ATTRIBUTE_DIRECTORY) /* Asked for a directory and it isn't. */
		return NT_STATUS_OBJECT_NAME_INVALID;
#endif /* JRATEST */

	/* On open checks the open itself will check the share mode, so
	   don't do it here as we'll get it wrong. */

	status = SMB_VFS_CREATE_FILE
		(conn,			/* conn */
		 req,			/* req */
		 0,			/* root_dir_fid */
		 smb_fname,		/* fname */
		 DELETE_ACCESS,		/* access_mask */
		 FILE_SHARE_NONE,	/* share_access */
		 FILE_OPEN,		/* create_disposition*/
		 FILE_NON_DIRECTORY_FILE, /* create_options */
		 			/* file_attributes */
		 posix_paths ? FILE_FLAG_POSIX_SEMANTICS|0777 :
				FILE_ATTRIBUTE_NORMAL,
		 0,			/* oplock_request */
		 NULL,			/* lease */
		 0,			/* allocation_size */
		 0,			/* private_flags */
		 NULL,			/* sd */
		 NULL,			/* ea_list */
		 &fsp,			/* result */
		 NULL,			/* pinfo */
		 NULL, NULL);		/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("SMB_VFS_CREATEFILE failed: %s\n",
			   nt_errstr(status)));
		return status;
	}

	status = can_set_delete_on_close(fsp, fattr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("do_unlink can_set_delete_on_close for file %s - "
			"(%s)\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status)));
		close_file(req, fsp, NORMAL_CLOSE);
		return status;
	}

	/* The set is across all open files on this dev/inode pair. */
	if (!set_delete_on_close(fsp, True,
				conn->session_info->security_token,
				conn->session_info->unix_token)) {
		close_file(req, fsp, NORMAL_CLOSE);
		return NT_STATUS_ACCESS_DENIED;
	}

	return close_file(req, fsp, NORMAL_CLOSE);
}

/****************************************************************************
 The guts of the unlink command, split out so it may be called by the NT SMB
 code.
****************************************************************************/

NTSTATUS unlink_internals(connection_struct *conn, struct smb_request *req,
			  uint32_t dirtype, struct smb_filename *smb_fname,
			  bool has_wild)
{
	char *fname_dir = NULL;
	char *fname_mask = NULL;
	int count=0;
	NTSTATUS status = NT_STATUS_OK;
	struct smb_filename *smb_fname_dir = NULL;
	TALLOC_CTX *ctx = talloc_tos();

	/* Split up the directory from the filename/mask. */
	status = split_fname_dir_mask(ctx, smb_fname->base_name,
				      &fname_dir, &fname_mask);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!VALID_STAT(smb_fname->st) &&
	    mangle_is_mangled(fname_mask, conn->params)) {
		char *new_mask = NULL;
		mangle_lookup_name_from_8_3(ctx, fname_mask,
					    &new_mask, conn->params);
		if (new_mask) {
			TALLOC_FREE(fname_mask);
			fname_mask = new_mask;
		}
	}

	if (!has_wild) {

		/*
		 * Only one file needs to be unlinked. Append the mask back
		 * onto the directory.
		 */
		TALLOC_FREE(smb_fname->base_name);
		if (ISDOT(fname_dir)) {
			/* Ensure we use canonical names on open. */
			smb_fname->base_name = talloc_asprintf(smb_fname,
							"%s",
							fname_mask);
		} else {
			smb_fname->base_name = talloc_asprintf(smb_fname,
							"%s/%s",
							fname_dir,
							fname_mask);
		}
		if (!smb_fname->base_name) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		if (dirtype == 0) {
			dirtype = FILE_ATTRIBUTE_NORMAL;
		}

		status = check_name(conn, smb_fname->base_name);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = do_unlink(conn, req, smb_fname, dirtype);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		count++;
	} else {
		struct smb_Dir *dir_hnd = NULL;
		long offset = 0;
		const char *dname = NULL;
		char *talloced = NULL;

		if ((dirtype & SAMBA_ATTRIBUTES_MASK) == FILE_ATTRIBUTE_DIRECTORY) {
			status = NT_STATUS_OBJECT_NAME_INVALID;
			goto out;
		}
		if (dirtype == 0) {
			dirtype = FILE_ATTRIBUTE_NORMAL;
		}

		if (strequal(fname_mask,"????????.???")) {
			TALLOC_FREE(fname_mask);
			fname_mask = talloc_strdup(ctx, "*");
			if (!fname_mask) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
		}

		status = check_name(conn, fname_dir);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		smb_fname_dir = synthetic_smb_fname(talloc_tos(),
					fname_dir,
					NULL,
					NULL,
					smb_fname->flags);
		if (smb_fname_dir == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		dir_hnd = OpenDir(talloc_tos(), conn, smb_fname_dir, fname_mask,
				  dirtype);
		if (dir_hnd == NULL) {
			status = map_nt_error_from_unix(errno);
			goto out;
		}

		/* XXXX the CIFS spec says that if bit0 of the flags2 field is set then
		   the pattern matches against the long name, otherwise the short name 
		   We don't implement this yet XXXX
		*/

		status = NT_STATUS_NO_SUCH_FILE;

		while ((dname = ReadDirName(dir_hnd, &offset,
					    &smb_fname->st, &talloced))) {
			TALLOC_CTX *frame = talloc_stackframe();

			if (!is_visible_file(conn, fname_dir, dname,
					     &smb_fname->st, true)) {
				TALLOC_FREE(frame);
				TALLOC_FREE(talloced);
				continue;
			}

			/* Quick check for "." and ".." */
			if (ISDOT(dname) || ISDOTDOT(dname)) {
				TALLOC_FREE(frame);
				TALLOC_FREE(talloced);
				continue;
			}

			if(!mask_match(dname, fname_mask,
				       conn->case_sensitive)) {
				TALLOC_FREE(frame);
				TALLOC_FREE(talloced);
				continue;
			}

			TALLOC_FREE(smb_fname->base_name);
			if (ISDOT(fname_dir)) {
				/* Ensure we use canonical names on open. */
				smb_fname->base_name =
					talloc_asprintf(smb_fname, "%s",
						dname);
			} else {
				smb_fname->base_name =
					talloc_asprintf(smb_fname, "%s/%s",
						fname_dir, dname);
			}

			if (!smb_fname->base_name) {
				TALLOC_FREE(dir_hnd);
				status = NT_STATUS_NO_MEMORY;
				TALLOC_FREE(frame);
				TALLOC_FREE(talloced);
				goto out;
			}

			status = check_name(conn, smb_fname->base_name);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(dir_hnd);
				TALLOC_FREE(frame);
				TALLOC_FREE(talloced);
				goto out;
			}

			status = do_unlink(conn, req, smb_fname, dirtype);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(dir_hnd);
				TALLOC_FREE(frame);
				TALLOC_FREE(talloced);
				goto out;
			}

			count++;
			DEBUG(3,("unlink_internals: successful unlink [%s]\n",
				 smb_fname->base_name));

			TALLOC_FREE(frame);
			TALLOC_FREE(talloced);
		}
		TALLOC_FREE(dir_hnd);
	}

	if (count == 0 && NT_STATUS_IS_OK(status) && errno != 0) {
		status = map_nt_error_from_unix(errno);
	}

 out:
	TALLOC_FREE(smb_fname_dir);
	TALLOC_FREE(fname_dir);
	TALLOC_FREE(fname_mask);
	return status;
}

/****************************************************************************
 Reply to a unlink
****************************************************************************/

void reply_unlink(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	struct smb_filename *smb_fname = NULL;
	uint32_t dirtype;
	NTSTATUS status;
	bool path_contains_wcard = False;
	uint32_t ucf_flags = UCF_COND_ALLOW_WCARD_LCOMP |
			(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBunlink);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	dirtype = SVAL(req->vwv+0, 0);

	srvstr_get_path_req_wcard(ctx, req, &name, (const char *)req->buf + 1,
				  STR_TERMINATE, &status,
				  &path_contains_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert(ctx, conn,
				  req->flags2 & FLAGS2_DFS_PATHNAMES,
				  name,
				  ucf_flags,
				  &path_contains_wcard,
				  &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	DEBUG(3,("reply_unlink : %s\n", smb_fname_str_dbg(smb_fname)));

	status = unlink_internals(conn, req, dirtype, smb_fname,
				  path_contains_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	reply_outbuf(req, 0, 0);
 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBunlink);
	return;
}

/****************************************************************************
 Fail for readbraw.
****************************************************************************/

static void fail_readraw(void)
{
	const char *errstr = talloc_asprintf(talloc_tos(),
			"FAIL ! reply_readbraw: socket write fail (%s)",
			strerror(errno));
	if (!errstr) {
		errstr = "";
	}
	exit_server_cleanly(errstr);
}

/****************************************************************************
 Fake (read/write) sendfile. Returns -1 on read or write fail.
****************************************************************************/

ssize_t fake_sendfile(struct smbXsrv_connection *xconn, files_struct *fsp,
		      off_t startpos, size_t nread)
{
	size_t bufsize;
	size_t tosend = nread;
	char *buf;

	if (nread == 0) {
		return 0;
	}

	bufsize = MIN(nread, 65536);

	if (!(buf = SMB_MALLOC_ARRAY(char, bufsize))) {
		return -1;
	}

	while (tosend > 0) {
		ssize_t ret;
		size_t cur_read;

		cur_read = MIN(tosend, bufsize);
		ret = read_file(fsp,buf,startpos,cur_read);
		if (ret == -1) {
			SAFE_FREE(buf);
			return -1;
		}

		/* If we had a short read, fill with zeros. */
		if (ret < cur_read) {
			memset(buf + ret, '\0', cur_read - ret);
		}

		ret = write_data(xconn->transport.sock, buf, cur_read);
		if (ret != cur_read) {
			int saved_errno = errno;
			/*
			 * Try and give an error message saying what
			 * client failed.
			 */
			DEBUG(0, ("write_data failed for client %s. "
				  "Error %s\n",
				  smbXsrv_connection_dbg(xconn),
				  strerror(saved_errno)));
			SAFE_FREE(buf);
			errno = saved_errno;
			return -1;
		}
		tosend -= cur_read;
		startpos += cur_read;
	}

	SAFE_FREE(buf);
	return (ssize_t)nread;
}

/****************************************************************************
 Deal with the case of sendfile reading less bytes from the file than
 requested. Fill with zeros (all we can do). Returns 0 on success
****************************************************************************/

ssize_t sendfile_short_send(struct smbXsrv_connection *xconn,
			    files_struct *fsp,
			    ssize_t nread,
			    size_t headersize,
			    size_t smb_maxcnt)
{
#define SHORT_SEND_BUFSIZE 1024
	if (nread < headersize) {
		DEBUG(0,("sendfile_short_send: sendfile failed to send "
			"header for file %s (%s). Terminating\n",
			fsp_str_dbg(fsp), strerror(errno)));
		return -1;
	}

	nread -= headersize;

	if (nread < smb_maxcnt) {
		char *buf = SMB_CALLOC_ARRAY(char, SHORT_SEND_BUFSIZE);
		if (!buf) {
			DEBUG(0,("sendfile_short_send: malloc failed "
				"for file %s (%s). Terminating\n",
				fsp_str_dbg(fsp), strerror(errno)));
			return -1;
		}

		DEBUG(0,("sendfile_short_send: filling truncated file %s "
			"with zeros !\n", fsp_str_dbg(fsp)));

		while (nread < smb_maxcnt) {
			/*
			 * We asked for the real file size and told sendfile
			 * to not go beyond the end of the file. But it can
			 * happen that in between our fstat call and the
			 * sendfile call the file was truncated. This is very
			 * bad because we have already announced the larger
			 * number of bytes to the client.
			 *
			 * The best we can do now is to send 0-bytes, just as
			 * a read from a hole in a sparse file would do.
			 *
			 * This should happen rarely enough that I don't care
			 * about efficiency here :-)
			 */
			size_t to_write;
			ssize_t ret;

			to_write = MIN(SHORT_SEND_BUFSIZE, smb_maxcnt - nread);
			ret = write_data(xconn->transport.sock, buf, to_write);
			if (ret != to_write) {
				int saved_errno = errno;
				/*
				 * Try and give an error message saying what
				 * client failed.
				 */
				DEBUG(0, ("write_data failed for client %s. "
					  "Error %s\n",
					  smbXsrv_connection_dbg(xconn),
					  strerror(saved_errno)));
				errno = saved_errno;
				return -1;
			}
			nread += to_write;
		}
		SAFE_FREE(buf);
	}

	return 0;
}

/****************************************************************************
 Return a readbraw error (4 bytes of zero).
****************************************************************************/

static void reply_readbraw_error(struct smbXsrv_connection *xconn)
{
	char header[4];

	SIVAL(header,0,0);

	smbd_lock_socket(xconn);
	if (write_data(xconn->transport.sock,header,4) != 4) {
		int saved_errno = errno;
		/*
		 * Try and give an error message saying what
		 * client failed.
		 */
		DEBUG(0, ("write_data failed for client %s. "
			  "Error %s\n",
			  smbXsrv_connection_dbg(xconn),
			  strerror(saved_errno)));
		errno = saved_errno;

		fail_readraw();
	}
	smbd_unlock_socket(xconn);
}

/****************************************************************************
 Use sendfile in readbraw.
****************************************************************************/

static void send_file_readbraw(connection_struct *conn,
			       struct smb_request *req,
			       files_struct *fsp,
			       off_t startpos,
			       size_t nread,
			       ssize_t mincount)
{
	struct smbXsrv_connection *xconn = req->xconn;
	char *outbuf = NULL;
	ssize_t ret=0;

	/*
	 * We can only use sendfile on a non-chained packet 
	 * but we can use on a non-oplocked file. tridge proved this
	 * on a train in Germany :-). JRA.
	 * reply_readbraw has already checked the length.
	 */

	if ( !req_is_in_chain(req) && (nread > 0) && (fsp->base_fsp == NULL) &&
	    (fsp->wcp == NULL) &&
	    lp_use_sendfile(SNUM(conn), xconn->smb1.signing_state) ) {
		ssize_t sendfile_read = -1;
		char header[4];
		DATA_BLOB header_blob;

		_smb_setlen(header,nread);
		header_blob = data_blob_const(header, 4);

		sendfile_read = SMB_VFS_SENDFILE(xconn->transport.sock, fsp,
						 &header_blob, startpos,
						 nread);
		if (sendfile_read == -1) {
			/* Returning ENOSYS means no data at all was sent.
			 * Do this as a normal read. */
			if (errno == ENOSYS) {
				goto normal_readbraw;
			}

			/*
			 * Special hack for broken Linux with no working sendfile. If we
			 * return EINTR we sent the header but not the rest of the data.
			 * Fake this up by doing read/write calls.
			 */
			if (errno == EINTR) {
				/* Ensure we don't do this again. */
				set_use_sendfile(SNUM(conn), False);
				DEBUG(0,("send_file_readbraw: sendfile not available. Faking..\n"));

				if (fake_sendfile(xconn, fsp, startpos, nread) == -1) {
					DEBUG(0,("send_file_readbraw: "
						 "fake_sendfile failed for "
						 "file %s (%s).\n",
						 fsp_str_dbg(fsp),
						 strerror(errno)));
					exit_server_cleanly("send_file_readbraw fake_sendfile failed");
				}
				return;
			}

			DEBUG(0,("send_file_readbraw: sendfile failed for "
				 "file %s (%s). Terminating\n",
				 fsp_str_dbg(fsp), strerror(errno)));
			exit_server_cleanly("send_file_readbraw sendfile failed");
		} else if (sendfile_read == 0) {
			/*
			 * Some sendfile implementations return 0 to indicate
			 * that there was a short read, but nothing was
			 * actually written to the socket.  In this case,
			 * fallback to the normal read path so the header gets
			 * the correct byte count.
			 */
			DEBUG(3, ("send_file_readbraw: sendfile sent zero "
				  "bytes falling back to the normal read: "
				  "%s\n", fsp_str_dbg(fsp)));
			goto normal_readbraw;
		}

		/* Deal with possible short send. */
		if (sendfile_read != 4+nread) {
			ret = sendfile_short_send(xconn, fsp,
						  sendfile_read, 4, nread);
			if (ret == -1) {
				fail_readraw();
			}
		}
		return;
	}

normal_readbraw:

	outbuf = talloc_array(NULL, char, nread+4);
	if (!outbuf) {
		DEBUG(0,("send_file_readbraw: talloc_array failed for size %u.\n",
			(unsigned)(nread+4)));
		reply_readbraw_error(xconn);
		return;
	}

	if (nread > 0) {
		ret = read_file(fsp,outbuf+4,startpos,nread);
#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
		if (ret < mincount)
			ret = 0;
#else
		if (ret < nread)
			ret = 0;
#endif
	}

	_smb_setlen(outbuf,ret);
	if (write_data(xconn->transport.sock, outbuf, 4+ret) != 4+ret) {
		int saved_errno = errno;
		/*
		 * Try and give an error message saying what
		 * client failed.
		 */
		DEBUG(0, ("write_data failed for client %s. Error %s\n",
			  smbXsrv_connection_dbg(xconn),
			  strerror(saved_errno)));
		errno = saved_errno;

		fail_readraw();
	}

	TALLOC_FREE(outbuf);
}

/****************************************************************************
 Reply to a readbraw (core+ protocol).
****************************************************************************/

void reply_readbraw(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smbXsrv_connection *xconn = req->xconn;
	ssize_t maxcount,mincount;
	size_t nread = 0;
	off_t startpos;
	files_struct *fsp;
	struct lock_struct lock;
	off_t size = 0;

	START_PROFILE(SMBreadbraw);

	if (srv_is_signing_active(xconn) || req->encrypted) {
		exit_server_cleanly("reply_readbraw: SMB signing/sealing is active - "
			"raw reads/writes are disallowed.");
	}

	if (req->wct < 8) {
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	if (xconn->smb1.echo_handler.trusted_fde) {
		DEBUG(2,("SMBreadbraw rejected with NOT_SUPPORTED because of "
			 "'async smb echo handler = yes'\n"));
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	/*
	 * Special check if an oplock break has been issued
	 * and the readraw request croses on the wire, we must
	 * return a zero length response here.
	 */

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	/*
	 * We have to do a check_fsp by hand here, as
	 * we must always return 4 zero bytes on error,
	 * not a NTSTATUS.
	 */

	if (!fsp || !conn || conn != fsp->conn ||
			req->vuid != fsp->vuid ||
			fsp->is_directory || fsp->fh->fd == -1) {
		/*
		 * fsp could be NULL here so use the value from the packet. JRA.
		 */
		DEBUG(3,("reply_readbraw: fnum %d not valid "
			"- cache prime?\n",
			(int)SVAL(req->vwv+0, 0)));
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	/* Do a "by hand" version of CHECK_READ. */
	if (!(fsp->can_read ||
			((req->flags2 & FLAGS2_READ_PERMIT_EXECUTE) &&
				(fsp->access_mask & FILE_EXECUTE)))) {
		DEBUG(3,("reply_readbraw: fnum %d not readable.\n",
				(int)SVAL(req->vwv+0, 0)));
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	flush_write_cache(fsp, SAMBA_READRAW_FLUSH);

	startpos = IVAL_TO_SMB_OFF_T(req->vwv+1, 0);
	if(req->wct == 10) {
		/*
		 * This is a large offset (64 bit) read.
		 */

		startpos |= (((off_t)IVAL(req->vwv+8, 0)) << 32);

		if(startpos < 0) {
			DEBUG(0,("reply_readbraw: negative 64 bit "
				"readraw offset (%.0f) !\n",
				(double)startpos ));
			reply_readbraw_error(xconn);
			END_PROFILE(SMBreadbraw);
			return;
		}
	}

	maxcount = (SVAL(req->vwv+3, 0) & 0xFFFF);
	mincount = (SVAL(req->vwv+4, 0) & 0xFFFF);

	/* ensure we don't overrun the packet size */
	maxcount = MIN(65535,maxcount);

	init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
	    (uint64_t)startpos, (uint64_t)maxcount, READ_LOCK,
	    &lock);

	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	if (fsp_stat(fsp) == 0) {
		size = fsp->fsp_name->st.st_ex_size;
	}

	if (startpos >= size) {
		nread = 0;
	} else {
		nread = MIN(maxcount,(size - startpos));
	}

#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
	if (nread < mincount)
		nread = 0;
#endif

	DEBUG( 3, ( "reply_readbraw: %s start=%.0f max=%lu "
		"min=%lu nread=%lu\n",
		fsp_fnum_dbg(fsp), (double)startpos,
		(unsigned long)maxcount,
		(unsigned long)mincount,
		(unsigned long)nread ) );

	send_file_readbraw(conn, req, fsp, startpos, nread, mincount);

	DEBUG(5,("reply_readbraw finished\n"));

	SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);

	END_PROFILE(SMBreadbraw);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a lockread (core+ protocol).
****************************************************************************/

void reply_lockread(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	ssize_t nread = -1;
	char *data;
	off_t startpos;
	size_t numtoread;
	size_t maxtoread;
	NTSTATUS status;
	files_struct *fsp;
	struct byte_range_lock *br_lck = NULL;
	char *p = NULL;
	struct smbXsrv_connection *xconn = req->xconn;

	START_PROFILE(SMBlockread);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockread);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlockread);
		return;
	}

	if (!CHECK_READ(fsp,req)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBlockread);
		return;
	}

	numtoread = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);

	/*
	 * NB. Discovered by Menny Hamburger at Mainsoft. This is a core+
	 * protocol request that predates the read/write lock concept. 
	 * Thus instead of asking for a read lock here we need to ask
	 * for a write lock. JRA.
	 * Note that the requested lock size is unaffected by max_send.
	 */

	br_lck = do_lock(req->sconn->msg_ctx,
			fsp,
			(uint64_t)req->smbpid,
			(uint64_t)numtoread,
			(uint64_t)startpos,
			WRITE_LOCK,
			WINDOWS_LOCK,
			False, /* Non-blocking lock. */
			&status,
			NULL);
	TALLOC_FREE(br_lck);

	if (NT_STATUS_V(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBlockread);
		return;
	}

	/*
	 * However the requested READ size IS affected by max_send. Insanity.... JRA.
	 */
	maxtoread = xconn->smb1.sessions.max_send - (smb_size + 5*2 + 3);

	if (numtoread > maxtoread) {
		DEBUG(0,("reply_lockread: requested read size (%u) is greater than maximum allowed (%u/%u). \
Returning short read of maximum allowed for compatibility with Windows 2000.\n",
			(unsigned int)numtoread, (unsigned int)maxtoread,
			(unsigned int)xconn->smb1.sessions.max_send));
		numtoread = maxtoread;
	}

	reply_outbuf(req, 5, numtoread + 3);

	data = smb_buf(req->outbuf) + 3;

	nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		END_PROFILE(SMBlockread);
		return;
	}

	srv_set_message((char *)req->outbuf, 5, nread+3, False);

	SSVAL(req->outbuf,smb_vwv0,nread);
	SSVAL(req->outbuf,smb_vwv5,nread+3);
	p = smb_buf(req->outbuf);
	SCVAL(p,0,0); /* pad byte. */
	SSVAL(p,1,nread);

	DEBUG(3,("lockread %s num=%d nread=%d\n",
		 fsp_fnum_dbg(fsp), (int)numtoread, (int)nread));

	END_PROFILE(SMBlockread);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a read.
****************************************************************************/

void reply_read(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtoread;
	size_t maxtoread;
	ssize_t nread = 0;
	char *data;
	off_t startpos;
	files_struct *fsp;
	struct lock_struct lock;
	struct smbXsrv_connection *xconn = req->xconn;

	START_PROFILE(SMBread);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBread);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBread);
		return;
	}

	if (!CHECK_READ(fsp,req)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBread);
		return;
	}

	numtoread = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);

	/*
	 * The requested read size cannot be greater than max_send. JRA.
	 */
	maxtoread = xconn->smb1.sessions.max_send - (smb_size + 5*2 + 3);

	if (numtoread > maxtoread) {
		DEBUG(0,("reply_read: requested read size (%u) is greater than maximum allowed (%u/%u). \
Returning short read of maximum allowed for compatibility with Windows 2000.\n",
			(unsigned int)numtoread, (unsigned int)maxtoread,
			(unsigned int)xconn->smb1.sessions.max_send));
		numtoread = maxtoread;
	}

	reply_outbuf(req, 5, numtoread+3);

	data = smb_buf(req->outbuf) + 3;

	init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
	    (uint64_t)startpos, (uint64_t)numtoread, READ_LOCK,
	    &lock);

	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
		reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		END_PROFILE(SMBread);
		return;
	}

	if (numtoread > 0)
		nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		goto strict_unlock;
	}

	srv_set_message((char *)req->outbuf, 5, nread+3, False);

	SSVAL(req->outbuf,smb_vwv0,nread);
	SSVAL(req->outbuf,smb_vwv5,nread+3);
	SCVAL(smb_buf(req->outbuf),0,1);
	SSVAL(smb_buf(req->outbuf),1,nread);

	DEBUG(3, ("read %s num=%d nread=%d\n",
		  fsp_fnum_dbg(fsp), (int)numtoread, (int)nread));

strict_unlock:
	SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);

	END_PROFILE(SMBread);
	return;
}

/****************************************************************************
 Setup readX header.
****************************************************************************/

int setup_readX_header(char *outbuf, size_t smb_maxcnt)
{
	int outsize;

	outsize = srv_set_message(outbuf,12,smb_maxcnt + 1 /* padding byte */,
				  False);

	memset(outbuf+smb_vwv0,'\0',24); /* valgrind init. */

	SCVAL(outbuf,smb_vwv0,0xFF);
	SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
	SSVAL(outbuf,smb_vwv5,smb_maxcnt);
	SSVAL(outbuf,smb_vwv6,
	      (smb_wct - 4)	/* offset from smb header to wct */
	      + 1 		/* the wct field */
	      + 12 * sizeof(uint16_t) /* vwv */
	      + 2		/* the buflen field */
	      + 1);		/* padding byte */
	SSVAL(outbuf,smb_vwv7,(smb_maxcnt >> 16));
	SCVAL(smb_buf(outbuf), 0, 0); /* padding byte */
	/* Reset the outgoing length, set_message truncates at 0x1FFFF. */
	_smb_setlen_large(outbuf,
			  smb_size + 12*2 + smb_maxcnt - 4 + 1 /* pad */);
	return outsize;
}

/****************************************************************************
 Reply to a read and X - possibly using sendfile.
****************************************************************************/

static void send_file_readX(connection_struct *conn, struct smb_request *req,
			    files_struct *fsp, off_t startpos,
			    size_t smb_maxcnt)
{
	struct smbXsrv_connection *xconn = req->xconn;
	ssize_t nread = -1;
	struct lock_struct lock;
	int saved_errno = 0;

	init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
	    (uint64_t)startpos, (uint64_t)smb_maxcnt, READ_LOCK,
	    &lock);

	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
		reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		return;
	}

	/*
	 * We can only use sendfile on a non-chained packet
	 * but we can use on a non-oplocked file. tridge proved this
	 * on a train in Germany :-). JRA.
	 */

	if (!req_is_in_chain(req) &&
	    !req->encrypted &&
	    (fsp->base_fsp == NULL) &&
	    (fsp->wcp == NULL) &&
	    lp_use_sendfile(SNUM(conn), xconn->smb1.signing_state) ) {
		uint8_t headerbuf[smb_size + 12 * 2 + 1 /* padding byte */];
		DATA_BLOB header;

		if(fsp_stat(fsp) == -1) {
			reply_nterror(req, map_nt_error_from_unix(errno));
			goto strict_unlock;
		}

		if (!S_ISREG(fsp->fsp_name->st.st_ex_mode) ||
		    (startpos > fsp->fsp_name->st.st_ex_size) ||
		    (smb_maxcnt > (fsp->fsp_name->st.st_ex_size - startpos))) {
			/*
			 * We already know that we would do a short read, so don't
			 * try the sendfile() path.
			 */
			goto nosendfile_read;
		}

		/*
		 * Set up the packet header before send. We
		 * assume here the sendfile will work (get the
		 * correct amount of data).
		 */

		header = data_blob_const(headerbuf, sizeof(headerbuf));

		construct_reply_common_req(req, (char *)headerbuf);
		setup_readX_header((char *)headerbuf, smb_maxcnt);

		nread = SMB_VFS_SENDFILE(xconn->transport.sock, fsp, &header,
					 startpos, smb_maxcnt);
		if (nread == -1) {
			saved_errno = errno;

			/* Returning ENOSYS means no data at all was sent.
			   Do this as a normal read. */
			if (errno == ENOSYS) {
				goto normal_read;
			}

			/*
			 * Special hack for broken Linux with no working sendfile. If we
			 * return EINTR we sent the header but not the rest of the data.
			 * Fake this up by doing read/write calls.
			 */

			if (errno == EINTR) {
				/* Ensure we don't do this again. */
				set_use_sendfile(SNUM(conn), False);
				DEBUG(0,("send_file_readX: sendfile not available. Faking..\n"));
				nread = fake_sendfile(xconn, fsp, startpos,
						      smb_maxcnt);
				if (nread == -1) {
					saved_errno = errno;
					DEBUG(0,("send_file_readX: "
						 "fake_sendfile failed for "
						 "file %s (%s) for client %s. "
						 "Terminating\n",
						 fsp_str_dbg(fsp),
						 smbXsrv_connection_dbg(xconn),
						 strerror(saved_errno)));
					errno = saved_errno;
					exit_server_cleanly("send_file_readX: fake_sendfile failed");
				}
				DEBUG(3, ("send_file_readX: fake_sendfile %s max=%d nread=%d\n",
					  fsp_fnum_dbg(fsp), (int)smb_maxcnt, (int)nread));
				/* No outbuf here means successful sendfile. */
				goto strict_unlock;
			}

			DEBUG(0,("send_file_readX: sendfile failed for file "
				 "%s (%s). Terminating\n", fsp_str_dbg(fsp),
				 strerror(errno)));
			exit_server_cleanly("send_file_readX sendfile failed");
		} else if (nread == 0) {
			/*
			 * Some sendfile implementations return 0 to indicate
			 * that there was a short read, but nothing was
			 * actually written to the socket.  In this case,
			 * fallback to the normal read path so the header gets
			 * the correct byte count.
			 */
			DEBUG(3, ("send_file_readX: sendfile sent zero bytes "
				  "falling back to the normal read: %s\n",
				  fsp_str_dbg(fsp)));
			goto normal_read;
		}

		DEBUG(3, ("send_file_readX: sendfile %s max=%d nread=%d\n",
			  fsp_fnum_dbg(fsp), (int)smb_maxcnt, (int)nread));

		/* Deal with possible short send. */
		if (nread != smb_maxcnt + sizeof(headerbuf)) {
			ssize_t ret;

			ret = sendfile_short_send(xconn, fsp, nread,
						  sizeof(headerbuf), smb_maxcnt);
			if (ret == -1) {
				const char *r;
				r = "send_file_readX: sendfile_short_send failed";
				DEBUG(0,("%s for file %s (%s).\n",
					 r, fsp_str_dbg(fsp), strerror(errno)));
				exit_server_cleanly(r);
			}
		}
		/* No outbuf here means successful sendfile. */
		SMB_PERFCOUNT_SET_MSGLEN_OUT(&req->pcd, nread);
		SMB_PERFCOUNT_END(&req->pcd);
		goto strict_unlock;
	}

normal_read:

	if ((smb_maxcnt & 0xFF0000) > 0x10000) {
		uint8_t headerbuf[smb_size + 2*12 + 1 /* padding byte */];
		ssize_t ret;

		if (!S_ISREG(fsp->fsp_name->st.st_ex_mode) ||
		    (startpos > fsp->fsp_name->st.st_ex_size) ||
		    (smb_maxcnt > (fsp->fsp_name->st.st_ex_size - startpos))) {
			/*
			 * We already know that we would do a short
			 * read, so don't try the sendfile() path.
			 */
			goto nosendfile_read;
		}

		construct_reply_common_req(req, (char *)headerbuf);
		setup_readX_header((char *)headerbuf, smb_maxcnt);

		/* Send out the header. */
		ret = write_data(xconn->transport.sock, (char *)headerbuf,
				 sizeof(headerbuf));
		if (ret != sizeof(headerbuf)) {
			saved_errno = errno;
			/*
			 * Try and give an error message saying what
			 * client failed.
			 */
			DEBUG(0,("send_file_readX: write_data failed for file "
				 "%s (%s) for client %s. Terminating\n",
				 fsp_str_dbg(fsp),
				 smbXsrv_connection_dbg(xconn),
				 strerror(saved_errno)));
			errno = saved_errno;
			exit_server_cleanly("send_file_readX sendfile failed");
		}
		nread = fake_sendfile(xconn, fsp, startpos, smb_maxcnt);
		if (nread == -1) {
			saved_errno = errno;
			DEBUG(0,("send_file_readX: fake_sendfile failed for file "
				 "%s (%s) for client %s. Terminating\n",
				 fsp_str_dbg(fsp),
				 smbXsrv_connection_dbg(xconn),
				 strerror(saved_errno)));
			errno = saved_errno;
			exit_server_cleanly("send_file_readX: fake_sendfile failed");
		}
		goto strict_unlock;
	}

nosendfile_read:

	reply_outbuf(req, 12, smb_maxcnt + 1 /* padding byte */);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	nread = read_file(fsp, smb_buf(req->outbuf) + 1 /* padding byte */,
			  startpos, smb_maxcnt);
	saved_errno = errno;

	SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);

	if (nread < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		return;
	}

	setup_readX_header((char *)req->outbuf, nread);

	DEBUG(3, ("send_file_readX %s max=%d nread=%d\n",
		  fsp_fnum_dbg(fsp), (int)smb_maxcnt, (int)nread));
	return;

 strict_unlock:
	SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
	TALLOC_FREE(req->outbuf);
	return;
}

/****************************************************************************
 Work out how much space we have for a read return.
****************************************************************************/

static size_t calc_max_read_pdu(const struct smb_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;

	if (xconn->protocol < PROTOCOL_NT1) {
		return xconn->smb1.sessions.max_send;
	}

	if (!lp_large_readwrite()) {
		return xconn->smb1.sessions.max_send;
	}

	if (req_is_in_chain(req)) {
		return xconn->smb1.sessions.max_send;
	}

	if (req->encrypted) {
		/*
		 * Don't take encrypted traffic up to the
		 * limit. There are padding considerations
		 * that make that tricky.
		 */
		return xconn->smb1.sessions.max_send;
	}

	if (srv_is_signing_active(xconn)) {
		return 0x1FFFF;
	}

	if (!lp_unix_extensions()) {
		return 0x1FFFF;
	}

	/*
	 * We can do ultra-large POSIX reads.
	 */
	return 0xFFFFFF;
}

/****************************************************************************
 Calculate how big a read can be. Copes with all clients. It's always
 safe to return a short read - Windows does this.
****************************************************************************/

static size_t calc_read_size(const struct smb_request *req,
			     size_t upper_size,
			     size_t lower_size)
{
	struct smbXsrv_connection *xconn = req->xconn;
	size_t max_pdu = calc_max_read_pdu(req);
	size_t total_size = 0;
	size_t hdr_len = MIN_SMB_SIZE + VWV(12);
	size_t max_len = max_pdu - hdr_len - 1 /* padding byte */;

	/*
	 * Windows explicitly ignores upper size of 0xFFFF.
	 * See [MS-SMB].pdf <26> Section 2.2.4.2.1:
	 * We must do the same as these will never fit even in
	 * an extended size NetBIOS packet.
	 */
	if (upper_size == 0xFFFF) {
		upper_size = 0;
	}

	if (xconn->protocol < PROTOCOL_NT1) {
		upper_size = 0;
	}

	total_size = ((upper_size<<16) | lower_size);

	/*
	 * LARGE_READX test shows it's always safe to return
	 * a short read. Windows does so.
	 */
	return MIN(total_size, max_len);
}

/****************************************************************************
 Reply to a read and X.
****************************************************************************/

void reply_read_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	off_t startpos;
	size_t smb_maxcnt;
	size_t upper_size;
	bool big_readX = False;
#if 0
	size_t smb_mincnt = SVAL(req->vwv+6, 0);
#endif

	START_PROFILE(SMBreadX);

	if ((req->wct != 10) && (req->wct != 12)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+2, 0));
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+3, 0);
	smb_maxcnt = SVAL(req->vwv+5, 0);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		reply_pipe_read_and_X(req);
		END_PROFILE(SMBreadX);
		return;
	}

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBreadX);
		return;
	}

	if (!CHECK_READ(fsp,req)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBreadX);
		return;
	}

	upper_size = SVAL(req->vwv+7, 0);
	smb_maxcnt = calc_read_size(req, upper_size, smb_maxcnt);
	if (smb_maxcnt > (0x1FFFF - (MIN_SMB_SIZE + VWV(12)))) {
		/*
		 * This is a heuristic to avoid keeping large
		 * outgoing buffers around over long-lived aio
		 * requests.
		 */
		big_readX = True;
	}

	if (req->wct == 12) {
		/*
		 * This is a large offset (64 bit) read.
		 */
		startpos |= (((off_t)IVAL(req->vwv+10, 0)) << 32);

	}

	if (!big_readX) {
		NTSTATUS status = schedule_aio_read_and_X(conn,
					req,
					fsp,
					startpos,
					smb_maxcnt);
		if (NT_STATUS_IS_OK(status)) {
			/* Read scheduled - we're done. */
			goto out;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
			/* Real error - report to client. */
			END_PROFILE(SMBreadX);
			reply_nterror(req, status);
			return;
		}
		/* NT_STATUS_RETRY - fall back to sync read. */
	}

	smbd_lock_socket(req->xconn);
	send_file_readX(conn, req, fsp,	startpos, smb_maxcnt);
	smbd_unlock_socket(req->xconn);

 out:
	END_PROFILE(SMBreadX);
	return;
}

/****************************************************************************
 Error replies to writebraw must have smb_wct == 1. Fix this up.
****************************************************************************/

void error_to_writebrawerr(struct smb_request *req)
{
	uint8_t *old_outbuf = req->outbuf;

	reply_outbuf(req, 1, 0);

	memcpy(req->outbuf, old_outbuf, smb_size);
	TALLOC_FREE(old_outbuf);
}

/****************************************************************************
 Read 4 bytes of a smb packet and return the smb length of the packet.
 Store the result in the buffer. This version of the function will
 never return a session keepalive (length of zero).
 Timeout is in milliseconds.
****************************************************************************/

static NTSTATUS read_smb_length(int fd, char *inbuf, unsigned int timeout,
				size_t *len)
{
	uint8_t msgtype = NBSSkeepalive;

	while (msgtype == NBSSkeepalive) {
		NTSTATUS status;

		status = read_smb_length_return_keepalive(fd, inbuf, timeout,
							  len);
		if (!NT_STATUS_IS_OK(status)) {
			char addr[INET6_ADDRSTRLEN];
			/* Try and give an error message
			 * saying what client failed. */
			DEBUG(0, ("read_fd_with_timeout failed for "
				  "client %s read error = %s.\n",
				  get_peer_addr(fd,addr,sizeof(addr)),
				  nt_errstr(status)));
			return status;
		}

		msgtype = CVAL(inbuf, 0);
	}

	DEBUG(10,("read_smb_length: got smb length of %lu\n",
		  (unsigned long)len));

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a writebraw (core+ or LANMAN1.0 protocol).
****************************************************************************/

void reply_writebraw(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smbXsrv_connection *xconn = req->xconn;
	char *buf = NULL;
	ssize_t nwritten=0;
	ssize_t total_written=0;
	size_t numtowrite=0;
	size_t tcount;
	off_t startpos;
	const char *data=NULL;
	bool write_through;
	files_struct *fsp;
	struct lock_struct lock;
	NTSTATUS status;

	START_PROFILE(SMBwritebraw);

	/*
	 * If we ever reply with an error, it must have the SMB command
	 * type of SMBwritec, not SMBwriteBraw, as this tells the client
	 * we're finished.
	 */
	SCVAL(discard_const_p(uint8_t, req->inbuf),smb_com,SMBwritec);

	if (srv_is_signing_active(xconn)) {
		END_PROFILE(SMBwritebraw);
		exit_server_cleanly("reply_writebraw: SMB signing is active - "
				"raw reads/writes are disallowed.");
	}

	if (req->wct < 12) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (xconn->smb1.echo_handler.trusted_fde) {
		DEBUG(2,("SMBwritebraw rejected with NOT_SUPPORTED because of "
			 "'async smb echo handler = yes'\n"));
		reply_nterror(req, NT_STATUS_NOT_SUPPORTED);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));
	if (!check_fsp(conn, req, fsp)) {
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	tcount = IVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+3, 0);
	write_through = BITSETW(req->vwv+7,0);

	/* We have to deal with slightly different formats depending
		on whether we are using the core+ or lanman1.0 protocol */

	if(get_Protocol() <= PROTOCOL_COREPLUS) {
		numtowrite = SVAL(smb_buf_const(req->inbuf),-2);
		data = smb_buf_const(req->inbuf);
	} else {
		numtowrite = SVAL(req->vwv+10, 0);
		data = smb_base(req->inbuf) + SVAL(req->vwv+11, 0);
	}

	/* Ensure we don't write bytes past the end of this packet. */
	if (data + numtowrite > smb_base(req->inbuf) + smb_len(req->inbuf)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (!fsp->print_file) {
		init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
		    (uint64_t)startpos, (uint64_t)tcount, WRITE_LOCK,
		    &lock);

		if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			error_to_writebrawerr(req);
			END_PROFILE(SMBwritebraw);
			return;
		}
	}

	if (numtowrite>0) {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}

	DEBUG(3, ("reply_writebraw: initial write %s start=%.0f num=%d "
			"wrote=%d sync=%d\n",
		fsp_fnum_dbg(fsp), (double)startpos, (int)numtowrite,
		(int)nwritten, (int)write_through));

	if (nwritten < (ssize_t)numtowrite)  {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		error_to_writebrawerr(req);
		goto strict_unlock;
	}

	total_written = nwritten;

	/* Allocate a buffer of 64k + length. */
	buf = talloc_array(NULL, char, 65540);
	if (!buf) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		error_to_writebrawerr(req);
		goto strict_unlock;
	}

	/* Return a SMBwritebraw message to the redirector to tell
	 * it to send more bytes */

	memcpy(buf, req->inbuf, smb_size);
	srv_set_message(buf,get_Protocol()>PROTOCOL_COREPLUS?1:0,0,True);
	SCVAL(buf,smb_com,SMBwritebraw);
	SSVALS(buf,smb_vwv0,0xFFFF);
	show_msg(buf);
	if (!srv_send_smb(req->xconn,
			  buf,
			  false, 0, /* no signing */
			  IS_CONN_ENCRYPTED(conn),
			  &req->pcd)) {
		exit_server_cleanly("reply_writebraw: srv_send_smb "
			"failed.");
	}

	/* Now read the raw data into the buffer and write it */
	status = read_smb_length(xconn->transport.sock, buf, SMB_SECONDARY_WAIT,
				 &numtowrite);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("secondary writebraw failed");
	}

	/* Set up outbuf to return the correct size */
	reply_outbuf(req, 1, 0);

	if (numtowrite != 0) {

		if (numtowrite > 0xFFFF) {
			DEBUG(0,("reply_writebraw: Oversize secondary write "
				"raw requested (%u). Terminating\n",
				(unsigned int)numtowrite ));
			exit_server_cleanly("secondary writebraw failed");
		}

		if (tcount > nwritten+numtowrite) {
			DEBUG(3,("reply_writebraw: Client overestimated the "
				"write %d %d %d\n",
				(int)tcount,(int)nwritten,(int)numtowrite));
		}

		status = read_data_ntstatus(xconn->transport.sock, buf+4,
					    numtowrite);

		if (!NT_STATUS_IS_OK(status)) {
			/* Try and give an error message
			 * saying what client failed. */
			DEBUG(0, ("reply_writebraw: Oversize secondary write "
				  "raw read failed (%s) for client %s. "
				  "Terminating\n", nt_errstr(status),
				  smbXsrv_connection_dbg(xconn)));
			exit_server_cleanly("secondary writebraw failed");
		}

		nwritten = write_file(req,fsp,buf+4,startpos+nwritten,numtowrite);
		if (nwritten == -1) {
			TALLOC_FREE(buf);
			reply_nterror(req, map_nt_error_from_unix(errno));
			error_to_writebrawerr(req);
			goto strict_unlock;
		}

		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(req->outbuf,smb_rcls,ERRHRD);
			SSVAL(req->outbuf,smb_err,ERRdiskfull);
		}

		if (nwritten > 0) {
			total_written += nwritten;
		}
 	}

	TALLOC_FREE(buf);
	SSVAL(req->outbuf,smb_vwv0,total_written);

	status = sync_file(conn, fsp, write_through);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_writebraw: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		error_to_writebrawerr(req);
		goto strict_unlock;
	}

	DEBUG(3,("reply_writebraw: secondart write %s start=%.0f num=%d "
		"wrote=%d\n",
		fsp_fnum_dbg(fsp), (double)startpos, (int)numtowrite,
		(int)total_written));

	if (!fsp->print_file) {
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
	}

	/* We won't return a status if write through is not selected - this
	 * follows what WfWg does */
	END_PROFILE(SMBwritebraw);

	if (!write_through && total_written==tcount) {

#if RABBIT_PELLET_FIX
		/*
		 * Fix for "rabbit pellet" mode, trigger an early TCP ack by
		 * sending a NBSSkeepalive. Thanks to DaveCB at Sun for this.
		 * JRA.
		 */
		if (!send_keepalive(xconn->transport.sock)) {
			exit_server_cleanly("reply_writebraw: send of "
				"keepalive failed");
		}
#endif
		TALLOC_FREE(req->outbuf);
	}
	return;

strict_unlock:
	if (!fsp->print_file) {
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
	}

	END_PROFILE(SMBwritebraw);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a writeunlock (core+).
****************************************************************************/

void reply_writeunlock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	ssize_t nwritten = -1;
	size_t numtowrite;
	off_t startpos;
	const char *data;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp;
	struct lock_struct lock;
	int saved_errno = 0;

	START_PROFILE(SMBwriteunlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwriteunlock);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	numtowrite = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);
	data = (const char *)req->buf + 3;

	if (!fsp->print_file && numtowrite > 0) {
		init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
		    (uint64_t)startpos, (uint64_t)numtowrite, WRITE_LOCK,
		    &lock);

		if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			END_PROFILE(SMBwriteunlock);
			return;
		}
	}

	/* The special X/Open SMB protocol handling of
	   zero length writes is *NOT* done for
	   this call */
	if(numtowrite == 0) {
		nwritten = 0;
	} else {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
		saved_errno = errno;
	}

	status = sync_file(conn, fsp, False /* write through */);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_writeunlock: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		goto strict_unlock;
	}

	if(nwritten < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		goto strict_unlock;
	}

	if((nwritten < numtowrite) && (numtowrite != 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto strict_unlock;
	}

	if (numtowrite && !fsp->print_file) {
		status = do_unlock(req->sconn->msg_ctx,
				fsp,
				(uint64_t)req->smbpid,
				(uint64_t)numtowrite, 
				(uint64_t)startpos,
				WINDOWS_LOCK);

		if (NT_STATUS_V(status)) {
			reply_nterror(req, status);
			goto strict_unlock;
		}
	}

	reply_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);

	DEBUG(3, ("writeunlock %s num=%d wrote=%d\n",
		  fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));

strict_unlock:
	if (numtowrite && !fsp->print_file) {
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
	}

	END_PROFILE(SMBwriteunlock);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a write.
****************************************************************************/

void reply_write(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtowrite;
	ssize_t nwritten = -1;
	off_t startpos;
	const char *data;
	files_struct *fsp;
	struct lock_struct lock;
	NTSTATUS status;
	int saved_errno = 0;

	START_PROFILE(SMBwrite);

	if (req->wct < 5) {
		END_PROFILE(SMBwrite);
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		reply_pipe_write(req);
		END_PROFILE(SMBwrite);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwrite);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBwrite);
		return;
	}

	numtowrite = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);
	data = (const char *)req->buf + 3;

	if (!fsp->print_file) {
		init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
			(uint64_t)startpos, (uint64_t)numtowrite, WRITE_LOCK,
			&lock);

		if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			END_PROFILE(SMBwrite);
			return;
		}
	}

	/*
	 * X/Open SMB protocol says that if smb_vwv1 is
	 * zero then the file size should be extended or
	 * truncated to the size given in smb_vwv[2-3].
	 */

	if(numtowrite == 0) {
		/*
		 * This is actually an allocate call, and set EOF. JRA.
		 */
		nwritten = vfs_allocate_file_space(fsp, (off_t)startpos);
		if (nwritten < 0) {
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto strict_unlock;
		}
		nwritten = vfs_set_filelen(fsp, (off_t)startpos);
		if (nwritten < 0) {
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto strict_unlock;
		}
		trigger_write_time_update_immediate(fsp);
	} else {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}

	status = sync_file(conn, fsp, False);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_write: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		goto strict_unlock;
	}

	if(nwritten < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		goto strict_unlock;
	}

	if((nwritten == 0) && (numtowrite != 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto strict_unlock;
	}

	reply_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);

	if (nwritten < (ssize_t)numtowrite) {
		SCVAL(req->outbuf,smb_rcls,ERRHRD);
		SSVAL(req->outbuf,smb_err,ERRdiskfull);
	}

	DEBUG(3, ("write %s num=%d wrote=%d\n", fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));

strict_unlock:
	if (!fsp->print_file) {
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
	}

	END_PROFILE(SMBwrite);
	return;
}

/****************************************************************************
 Ensure a buffer is a valid writeX for recvfile purposes.
****************************************************************************/

#define STANDARD_WRITE_AND_X_HEADER_SIZE (smb_size - 4 + /* basic header */ \
						(2*14) + /* word count (including bcc) */ \
						1 /* pad byte */)

bool is_valid_writeX_buffer(struct smbXsrv_connection *xconn,
			    const uint8_t *inbuf)
{
	size_t numtowrite;
	unsigned int doff = 0;
	size_t len = smb_len_large(inbuf);
	uint16_t fnum;
	struct smbXsrv_open *op = NULL;
	struct files_struct *fsp = NULL;
	NTSTATUS status;

	if (is_encrypted_packet(inbuf)) {
		/* Can't do this on encrypted
		 * connections. */
		return false;
	}

	if (CVAL(inbuf,smb_com) != SMBwriteX) {
		return false;
	}

	if (CVAL(inbuf,smb_vwv0) != 0xFF ||
			CVAL(inbuf,smb_wct) != 14) {
		DEBUG(10,("is_valid_writeX_buffer: chained or "
			"invalid word length.\n"));
		return false;
	}

	fnum = SVAL(inbuf, smb_vwv2);
	status = smb1srv_open_lookup(xconn,
				     fnum,
				     0, /* now */
				     &op);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("is_valid_writeX_buffer: bad fnum\n"));
		return false;
	}
	fsp = op->compat;
	if (fsp == NULL) {
		DEBUG(10,("is_valid_writeX_buffer: bad fsp\n"));
		return false;
	}
	if (fsp->conn == NULL) {
		DEBUG(10,("is_valid_writeX_buffer: bad fsp->conn\n"));
		return false;
	}

	if (IS_IPC(fsp->conn)) {
		DEBUG(10,("is_valid_writeX_buffer: IPC$ tid\n"));
		return false;
	}
	if (IS_PRINT(fsp->conn)) {
		DEBUG(10,("is_valid_writeX_buffer: printing tid\n"));
		return false;
	}
	doff = SVAL(inbuf,smb_vwv11);

	numtowrite = SVAL(inbuf,smb_vwv10);

	if (len > doff && len - doff > 0xFFFF) {
		numtowrite |= (((size_t)SVAL(inbuf,smb_vwv9))<<16);
	}

	if (numtowrite == 0) {
		DEBUG(10,("is_valid_writeX_buffer: zero write\n"));
		return false;
	}

	/* Ensure the sizes match up. */
	if (doff < STANDARD_WRITE_AND_X_HEADER_SIZE) {
		/* no pad byte...old smbclient :-( */
		DEBUG(10,("is_valid_writeX_buffer: small doff %u (min %u)\n",
			(unsigned int)doff,
			(unsigned int)STANDARD_WRITE_AND_X_HEADER_SIZE));
		return false;
	}

	if (len - doff != numtowrite) {
		DEBUG(10,("is_valid_writeX_buffer: doff mismatch "
			"len = %u, doff = %u, numtowrite = %u\n",
			(unsigned int)len,
			(unsigned int)doff,
			(unsigned int)numtowrite ));
		return false;
	}

	DEBUG(10,("is_valid_writeX_buffer: true "
		"len = %u, doff = %u, numtowrite = %u\n",
		(unsigned int)len,
		(unsigned int)doff,
		(unsigned int)numtowrite ));

	return true;
}

/****************************************************************************
 Reply to a write and X.
****************************************************************************/

void reply_write_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smbXsrv_connection *xconn = req->xconn;
	files_struct *fsp;
	struct lock_struct lock;
	off_t startpos;
	size_t numtowrite;
	bool write_through;
	ssize_t nwritten;
	unsigned int smb_doff;
	unsigned int smblen;
	const char *data;
	NTSTATUS status;
	int saved_errno = 0;

	START_PROFILE(SMBwriteX);

	if ((req->wct != 12) && (req->wct != 14)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	numtowrite = SVAL(req->vwv+10, 0);
	smb_doff = SVAL(req->vwv+11, 0);
	smblen = smb_len(req->inbuf);

	if (req->unread_bytes > 0xFFFF ||
			(smblen > smb_doff &&
				smblen - smb_doff > 0xFFFF)) {
		numtowrite |= (((size_t)SVAL(req->vwv+9, 0))<<16);
	}

	if (req->unread_bytes) {
		/* Can't do a recvfile write on IPC$ */
		if (IS_IPC(conn)) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	       	if (numtowrite != req->unread_bytes) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	} else {
		if (smb_doff > smblen || smb_doff + numtowrite < numtowrite ||
				smb_doff + numtowrite > smblen) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		if (req->unread_bytes) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
		reply_pipe_write_and_X(req);
		goto out;
	}

	fsp = file_fsp(req, SVAL(req->vwv+2, 0));
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+3, 0);
	write_through = BITSETW(req->vwv+7,0);

	if (!check_fsp(conn, req, fsp)) {
		goto out;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	data = smb_base(req->inbuf) + smb_doff;

	if(req->wct == 14) {
		/*
		 * This is a large offset (64 bit) write.
		 */
		startpos |= (((off_t)IVAL(req->vwv+12, 0)) << 32);

	}

	/* X/Open SMB protocol says that, unlike SMBwrite
	if the length is zero then NO truncation is
	done, just a write of zero. To truncate a file,
	use SMBwrite. */

	if(numtowrite == 0) {
		nwritten = 0;
	} else {
		if (req->unread_bytes == 0) {
			status = schedule_aio_write_and_X(conn,
						req,
						fsp,
						data,
						startpos,
						numtowrite);

			if (NT_STATUS_IS_OK(status)) {
				/* write scheduled - we're done. */
				goto out;
			}
			if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
				/* Real error - report to client. */
				reply_nterror(req, status);
				goto out;
			}
			/* NT_STATUS_RETRY - fall through to sync write. */
		}

		init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
		    (uint64_t)startpos, (uint64_t)numtowrite, WRITE_LOCK,
		    &lock);

		if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			goto out;
		}

		nwritten = write_file(req,fsp,data,startpos,numtowrite);
		saved_errno = errno;

		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
	}

	if(nwritten < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		goto out;
	}

	if((nwritten == 0) && (numtowrite != 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto out;
	}

	reply_outbuf(req, 6, 0);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */
	SSVAL(req->outbuf,smb_vwv2,nwritten);
	SSVAL(req->outbuf,smb_vwv4,nwritten>>16);

	DEBUG(3,("writeX %s num=%d wrote=%d\n",
		fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));

	status = sync_file(conn, fsp, write_through);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_write_and_X: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		goto out;
	}

	END_PROFILE(SMBwriteX);
	return;

out:
	if (req->unread_bytes) {
		/* writeX failed. drain socket. */
		if (drain_socket(xconn->transport.sock, req->unread_bytes) !=
				req->unread_bytes) {
			smb_panic("failed to drain pending bytes");
		}
		req->unread_bytes = 0;
	}

	END_PROFILE(SMBwriteX);
	return;
}

/****************************************************************************
 Reply to a lseek.
****************************************************************************/

void reply_lseek(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	off_t startpos;
	off_t res= -1;
	int mode,umode;
	files_struct *fsp;

	START_PROFILE(SMBlseek);

	if (req->wct < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlseek);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		return;
	}

	flush_write_cache(fsp, SAMBA_SEEK_FLUSH);

	mode = SVAL(req->vwv+1, 0) & 3;
	/* NB. This doesn't use IVAL_TO_SMB_OFF_T as startpos can be signed in this case. */
	startpos = (off_t)IVALS(req->vwv+2, 0);

	switch (mode) {
		case 0:
			umode = SEEK_SET;
			res = startpos;
			break;
		case 1:
			umode = SEEK_CUR;
			res = fsp->fh->pos + startpos;
			break;
		case 2:
			umode = SEEK_END;
			break;
		default:
			umode = SEEK_SET;
			res = startpos;
			break;
	}

	if (umode == SEEK_END) {
		if((res = SMB_VFS_LSEEK(fsp,startpos,umode)) == -1) {
			if(errno == EINVAL) {
				off_t current_pos = startpos;

				if(fsp_stat(fsp) == -1) {
					reply_nterror(req,
						map_nt_error_from_unix(errno));
					END_PROFILE(SMBlseek);
					return;
				}

				current_pos += fsp->fsp_name->st.st_ex_size;
				if(current_pos < 0)
					res = SMB_VFS_LSEEK(fsp,0,SEEK_SET);
			}
		}

		if(res == -1) {
			reply_nterror(req, map_nt_error_from_unix(errno));
			END_PROFILE(SMBlseek);
			return;
		}
	}

	fsp->fh->pos = res;

	reply_outbuf(req, 2, 0);
	SIVAL(req->outbuf,smb_vwv0,res);

	DEBUG(3,("lseek %s ofs=%.0f newpos = %.0f mode=%d\n",
		fsp_fnum_dbg(fsp), (double)startpos, (double)res, mode));

	END_PROFILE(SMBlseek);
	return;
}

/****************************************************************************
 Reply to a flush.
****************************************************************************/

void reply_flush(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint16_t fnum;
	files_struct *fsp;

	START_PROFILE(SMBflush);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fnum = SVAL(req->vwv+0, 0);
	fsp = file_fsp(req, fnum);

	if ((fnum != 0xFFFF) && !check_fsp(conn, req, fsp)) {
		return;
	}

	if (!fsp) {
		file_sync_all(conn);
	} else {
		NTSTATUS status = sync_file(conn, fsp, True);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5,("reply_flush: sync_file for %s returned %s\n",
				fsp_str_dbg(fsp), nt_errstr(status)));
			reply_nterror(req, status);
			END_PROFILE(SMBflush);
			return;
		}
	}

	reply_outbuf(req, 0, 0);

	DEBUG(3,("flush\n"));
	END_PROFILE(SMBflush);
	return;
}

/****************************************************************************
 Reply to a exit.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_exit(struct smb_request *req)
{
	START_PROFILE(SMBexit);

	file_close_pid(req->sconn, req->smbpid, req->vuid);

	reply_outbuf(req, 0, 0);

	DEBUG(3,("exit\n"));

	END_PROFILE(SMBexit);
	return;
}

struct reply_close_state {
	files_struct *fsp;
	struct smb_request *smbreq;
};

static void do_smb1_close(struct tevent_req *req);

void reply_close(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp = NULL;
	START_PROFILE(SMBclose);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBclose);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	/*
	 * We can only use check_fsp if we know it's not a directory.
	 */

	if (!check_fsp_open(conn, req, fsp)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		END_PROFILE(SMBclose);
		return;
	}

	DEBUG(3, ("Close %s fd=%d %s (numopen=%d)\n",
		  fsp->is_directory ? "directory" : "file",
		  fsp->fh->fd, fsp_fnum_dbg(fsp),
		  conn->num_files_open));

	if (!fsp->is_directory) {
		time_t t;

		/*
		 * Take care of any time sent in the close.
		 */

		t = srv_make_unix_date3(req->vwv+1);
		set_close_write_time(fsp, convert_time_t_to_timespec(t));
	}

	if (fsp->num_aio_requests != 0) {

		struct reply_close_state *state;

		DEBUG(10, ("closing with aio %u requests pending\n",
			   fsp->num_aio_requests));

		/*
		 * We depend on the aio_extra destructor to take care of this
		 * close request once fsp->num_aio_request drops to 0.
		 */

		fsp->deferred_close = tevent_wait_send(
			fsp, fsp->conn->sconn->ev_ctx);
		if (fsp->deferred_close == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		state = talloc(fsp, struct reply_close_state);
		if (state == NULL) {
			TALLOC_FREE(fsp->deferred_close);
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		state->fsp = fsp;
		state->smbreq = talloc_move(fsp, &req);
		tevent_req_set_callback(fsp->deferred_close, do_smb1_close,
					state);
		END_PROFILE(SMBclose);
		return;
	}

	/*
	 * close_file() returns the unix errno if an error was detected on
	 * close - normally this is due to a disk full error. If not then it
	 * was probably an I/O error.
	 */

	status = close_file(req, fsp, NORMAL_CLOSE);
done:
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBclose);
		return;
	}

	reply_outbuf(req, 0, 0);
	END_PROFILE(SMBclose);
	return;
}

static void do_smb1_close(struct tevent_req *req)
{
	struct reply_close_state *state = tevent_req_callback_data(
		req, struct reply_close_state);
	struct smb_request *smbreq;
	NTSTATUS status;
	int ret;

	ret = tevent_wait_recv(req);
	TALLOC_FREE(req);
	if (ret != 0) {
		DEBUG(10, ("tevent_wait_recv returned %s\n",
			   strerror(ret)));
		/*
		 * Continue anyway, this should never happen
		 */
	}

	/*
	 * fsp->smb2_close_request right now is a talloc grandchild of
	 * fsp. When we close_file(fsp), it would go with it. No chance to
	 * reply...
	 */
	smbreq = talloc_move(talloc_tos(), &state->smbreq);

	status = close_file(smbreq, state->fsp, NORMAL_CLOSE);
	if (NT_STATUS_IS_OK(status)) {
		reply_outbuf(smbreq, 0, 0);
	} else {
		reply_nterror(smbreq, status);
	}
	if (!srv_send_smb(smbreq->xconn,
			(char *)smbreq->outbuf,
			true,
			smbreq->seqnum+1,
			IS_CONN_ENCRYPTED(smbreq->conn)||smbreq->encrypted,
			NULL)) {
		exit_server_cleanly("handle_aio_read_complete: srv_send_smb "
				    "failed.");
	}
	TALLOC_FREE(smbreq);
}

/****************************************************************************
 Reply to a writeclose (Core+ protocol).
****************************************************************************/

void reply_writeclose(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtowrite;
	ssize_t nwritten = -1;
	NTSTATUS close_status = NT_STATUS_OK;
	off_t startpos;
	const char *data;
	struct timespec mtime;
	files_struct *fsp;
	struct lock_struct lock;

	START_PROFILE(SMBwriteclose);

	if (req->wct < 6) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteclose);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwriteclose);
		return;
	}
	if (!CHECK_WRITE(fsp)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBwriteclose);
		return;
	}

	numtowrite = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);
	mtime = convert_time_t_to_timespec(srv_make_unix_date3(req->vwv+4));
	data = (const char *)req->buf + 1;

	if (fsp->print_file == NULL) {
		init_strict_lock_struct(fsp, (uint64_t)req->smbpid,
		    (uint64_t)startpos, (uint64_t)numtowrite, WRITE_LOCK,
		    &lock);

		if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			END_PROFILE(SMBwriteclose);
			return;
		}
	}

	nwritten = write_file(req,fsp,data,startpos,numtowrite);

	if (fsp->print_file == NULL) {
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
	}

	set_close_write_time(fsp, mtime);

	/*
	 * More insanity. W2K only closes the file if writelen > 0.
	 * JRA.
	 */

	DEBUG(3,("writeclose %s num=%d wrote=%d (numopen=%d)\n",
		fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten,
		(numtowrite) ? conn->num_files_open - 1 : conn->num_files_open));

	if (numtowrite) {
		DEBUG(3,("reply_writeclose: zero length write doesn't close "
			 "file %s\n", fsp_str_dbg(fsp)));
		close_status = close_file(req, fsp, NORMAL_CLOSE);
		fsp = NULL;
	}

	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto out;
	}

	if(!NT_STATUS_IS_OK(close_status)) {
		reply_nterror(req, close_status);
		goto out;
	}

	reply_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);

out:

	END_PROFILE(SMBwriteclose);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a lock.
****************************************************************************/

void reply_lock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint64_t count,offset;
	NTSTATUS status;
	files_struct *fsp;
	struct byte_range_lock *br_lck = NULL;

	START_PROFILE(SMBlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlock);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlock);
		return;
	}

	count = (uint64_t)IVAL(req->vwv+1, 0);
	offset = (uint64_t)IVAL(req->vwv+3, 0);

	DEBUG(3,("lock fd=%d %s offset=%.0f count=%.0f\n",
		 fsp->fh->fd, fsp_fnum_dbg(fsp), (double)offset, (double)count));

	br_lck = do_lock(req->sconn->msg_ctx,
			fsp,
			(uint64_t)req->smbpid,
			count,
			offset,
			WRITE_LOCK,
			WINDOWS_LOCK,
			False, /* Non-blocking lock. */
			&status,
			NULL);

	TALLOC_FREE(br_lck);

	if (NT_STATUS_V(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBlock);
		return;
	}

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBlock);
	return;
}

/****************************************************************************
 Reply to a unlock.
****************************************************************************/

void reply_unlock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint64_t count,offset;
	NTSTATUS status;
	files_struct *fsp;

	START_PROFILE(SMBunlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBunlock);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBunlock);
		return;
	}

	count = (uint64_t)IVAL(req->vwv+1, 0);
	offset = (uint64_t)IVAL(req->vwv+3, 0);

	status = do_unlock(req->sconn->msg_ctx,
			fsp,
			(uint64_t)req->smbpid,
			count,
			offset,
			WINDOWS_LOCK);

	if (NT_STATUS_V(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBunlock);
		return;
	}

	DEBUG( 3, ( "unlock fd=%d %s offset=%.0f count=%.0f\n",
		    fsp->fh->fd, fsp_fnum_dbg(fsp), (double)offset, (double)count ) );

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBunlock);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a tdis.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tdis(struct smb_request *req)
{
	NTSTATUS status;
	connection_struct *conn = req->conn;
	struct smbXsrv_tcon *tcon;

	START_PROFILE(SMBtdis);

	if (!conn) {
		DEBUG(4,("Invalid connection in tdis\n"));
		reply_force_doserror(req, ERRSRV, ERRinvnid);
		END_PROFILE(SMBtdis);
		return;
	}

	tcon = conn->tcon;
	req->conn = NULL;

	/*
	 * TODO: cancel all outstanding requests on the tcon
	 */
	status = smbXsrv_tcon_disconnect(tcon, req->vuid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("reply_tdis: "
			  "smbXsrv_tcon_disconnect() failed: %s\n",
			  nt_errstr(status)));
		/*
		 * If we hit this case, there is something completely
		 * wrong, so we better disconnect the transport connection.
		 */
		END_PROFILE(SMBtdis);
		exit_server(__location__ ": smbXsrv_tcon_disconnect failed");
		return;
	}

	TALLOC_FREE(tcon);

	reply_outbuf(req, 0, 0);
	END_PROFILE(SMBtdis);
	return;
}

/****************************************************************************
 Reply to a echo.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_echo(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_perfcount_data local_pcd;
	struct smb_perfcount_data *cur_pcd;
	int smb_reverb;
	int seq_num;

	START_PROFILE(SMBecho);

	smb_init_perfcount_data(&local_pcd);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBecho);
		return;
	}

	smb_reverb = SVAL(req->vwv+0, 0);

	reply_outbuf(req, 1, req->buflen);

	/* copy any incoming data back out */
	if (req->buflen > 0) {
		memcpy(smb_buf(req->outbuf), req->buf, req->buflen);
	}

	if (smb_reverb > 100) {
		DEBUG(0,("large reverb (%d)?? Setting to 100\n",smb_reverb));
		smb_reverb = 100;
	}

	for (seq_num = 1 ; seq_num <= smb_reverb ; seq_num++) {

		/* this makes sure we catch the request pcd */
		if (seq_num == smb_reverb) {
			cur_pcd = &req->pcd;
		} else {
			SMB_PERFCOUNT_COPY_CONTEXT(&req->pcd, &local_pcd);
			cur_pcd = &local_pcd;
		}

		SSVAL(req->outbuf,smb_vwv0,seq_num);

		show_msg((char *)req->outbuf);
		if (!srv_send_smb(req->xconn,
				(char *)req->outbuf,
				true, req->seqnum+1,
				IS_CONN_ENCRYPTED(conn)||req->encrypted,
				cur_pcd))
			exit_server_cleanly("reply_echo: srv_send_smb failed.");
	}

	DEBUG(3,("echo %d times\n", smb_reverb));

	TALLOC_FREE(req->outbuf);

	END_PROFILE(SMBecho);
	return;
}

/****************************************************************************
 Reply to a printopen.
****************************************************************************/

void reply_printopen(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsplopen);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplopen);
		return;
	}

	if (!CAN_PRINT(conn)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsplopen);
		return;
	}

	status = file_new(req, conn, &fsp);
	if(!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsplopen);
		return;
	}

	/* Open for exclusive use, write only. */
	status = print_spool_open(fsp, NULL, req->vuid);

	if (!NT_STATUS_IS_OK(status)) {
		file_free(req, fsp);
		reply_nterror(req, status);
		END_PROFILE(SMBsplopen);
		return;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	DEBUG(3,("openprint fd=%d %s\n",
		 fsp->fh->fd, fsp_fnum_dbg(fsp)));

	END_PROFILE(SMBsplopen);
	return;
}

/****************************************************************************
 Reply to a printclose.
****************************************************************************/

void reply_printclose(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsplclose);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplclose);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBsplclose);
                return;
        }

	if (!CAN_PRINT(conn)) {
		reply_force_doserror(req, ERRSRV, ERRerror);
		END_PROFILE(SMBsplclose);
		return;
	}

	DEBUG(3,("printclose fd=%d %s\n",
		 fsp->fh->fd, fsp_fnum_dbg(fsp)));

	status = close_file(req, fsp, NORMAL_CLOSE);

	if(!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsplclose);
		return;
	}

	reply_outbuf(req, 0, 0);

	END_PROFILE(SMBsplclose);
	return;
}

/****************************************************************************
 Reply to a printqueue.
****************************************************************************/

void reply_printqueue(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int max_count;
	int start_index;

	START_PROFILE(SMBsplretq);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplretq);
		return;
	}

	max_count = SVAL(req->vwv+0, 0);
	start_index = SVAL(req->vwv+1, 0);

	/* we used to allow the client to get the cnum wrong, but that
	   is really quite gross and only worked when there was only
	   one printer - I think we should now only accept it if they
	   get it right (tridge) */
	if (!CAN_PRINT(conn)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsplretq);
		return;
	}

	reply_outbuf(req, 2, 3);
	SSVAL(req->outbuf,smb_vwv0,0);
	SSVAL(req->outbuf,smb_vwv1,0);
	SCVAL(smb_buf(req->outbuf),0,1);
	SSVAL(smb_buf(req->outbuf),1,0);

	DEBUG(3,("printqueue start_index=%d max_count=%d\n",
		 start_index, max_count));

	{
		TALLOC_CTX *mem_ctx = talloc_tos();
		NTSTATUS status;
		WERROR werr;
		const char *sharename = lp_servicename(mem_ctx, SNUM(conn));
		struct rpc_pipe_client *cli = NULL;
		struct dcerpc_binding_handle *b = NULL;
		struct policy_handle handle;
		struct spoolss_DevmodeContainer devmode_ctr;
		union spoolss_JobInfo *info;
		uint32_t count;
		uint32_t num_to_get;
		uint32_t first;
		uint32_t i;

		ZERO_STRUCT(handle);

		status = rpc_pipe_open_interface(conn,
						 &ndr_table_spoolss,
						 conn->session_info,
						 conn->sconn->remote_address,
						 conn->sconn->msg_ctx,
						 &cli);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("reply_printqueue: "
				  "could not connect to spoolss: %s\n",
				  nt_errstr(status)));
			reply_nterror(req, status);
			goto out;
		}
		b = cli->binding_handle;

		ZERO_STRUCT(devmode_ctr);

		status = dcerpc_spoolss_OpenPrinter(b, mem_ctx,
						sharename,
						NULL, devmode_ctr,
						SEC_FLAG_MAXIMUM_ALLOWED,
						&handle,
						&werr);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}
		if (!W_ERROR_IS_OK(werr)) {
			reply_nterror(req, werror_to_ntstatus(werr));
			goto out;
		}

		werr = rpccli_spoolss_enumjobs(cli, mem_ctx,
					       &handle,
					       0, /* firstjob */
					       0xff, /* numjobs */
					       2, /* level */
					       0, /* offered */
					       &count,
					       &info);
		if (!W_ERROR_IS_OK(werr)) {
			reply_nterror(req, werror_to_ntstatus(werr));
			goto out;
		}

		if (max_count > 0) {
			first = start_index;
		} else {
			first = start_index + max_count + 1;
		}

		if (first >= count) {
			num_to_get = first;
		} else {
			num_to_get = first + MIN(ABS(max_count), count - first);
		}

		for (i = first; i < num_to_get; i++) {
			char blob[28];
			char *p = blob;
			time_t qtime = spoolss_Time_to_time_t(&info[i].info2.submitted);
			int qstatus;
			size_t len = 0;
			uint16_t qrapjobid = pjobid_to_rap(sharename,
							info[i].info2.job_id);

			if (info[i].info2.status == JOB_STATUS_PRINTING) {
				qstatus = 2;
			} else {
				qstatus = 3;
			}

			srv_put_dos_date2(p, 0, qtime);
			SCVAL(p, 4, qstatus);
			SSVAL(p, 5, qrapjobid);
			SIVAL(p, 7, info[i].info2.size);
			SCVAL(p, 11, 0);
			status = srvstr_push(blob, req->flags2, p+12,
				    info[i].info2.notify_name, 16, STR_ASCII, &len);
			if (!NT_STATUS_IS_OK(status)) {
				reply_nterror(req, status);
				goto out;
			}
			if (message_push_blob(
				    &req->outbuf,
				    data_blob_const(
					    blob, sizeof(blob))) == -1) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}
		}

		if (count > 0) {
			SSVAL(req->outbuf,smb_vwv0,count);
			SSVAL(req->outbuf,smb_vwv1,
			      (max_count>0?first+count:first-1));
			SCVAL(smb_buf(req->outbuf),0,1);
			SSVAL(smb_buf(req->outbuf),1,28*count);
		}


		DEBUG(3, ("%u entries returned in queue\n",
			  (unsigned)count));

out:
		if (b && is_valid_policy_hnd(&handle)) {
			dcerpc_spoolss_ClosePrinter(b, mem_ctx, &handle, &werr);
		}

	}

	END_PROFILE(SMBsplretq);
	return;
}

/****************************************************************************
 Reply to a printwrite.
****************************************************************************/

void reply_printwrite(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int numtowrite;
	const char *data;
	files_struct *fsp;

	START_PROFILE(SMBsplwr);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplwr);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBsplwr);
                return;
        }

	if (!fsp->print_file) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsplwr);
		return;
	}

	if (!CHECK_WRITE(fsp)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsplwr);
		return;
	}

	numtowrite = SVAL(req->buf, 1);

	if (req->buflen < numtowrite + 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplwr);
		return;
	}

	data = (const char *)req->buf + 3;

	if (write_file(req,fsp,data,(off_t)-1,numtowrite) != numtowrite) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		END_PROFILE(SMBsplwr);
		return;
	}

	DEBUG(3, ("printwrite %s num=%d\n", fsp_fnum_dbg(fsp), numtowrite));

	END_PROFILE(SMBsplwr);
	return;
}

/****************************************************************************
 Reply to a mkdir.
****************************************************************************/

void reply_mkdir(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_dname = NULL;
	char *directory = NULL;
	NTSTATUS status;
	uint32_t ucf_flags = UCF_PREP_CREATEFILE |
			(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBmkdir);

	srvstr_get_path_req(ctx, req, &directory, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert(ctx, conn,
				 req->flags2 & FLAGS2_DFS_PATHNAMES,
				 directory,
				 ucf_flags,
				 NULL,
				 &smb_dname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = create_directory(conn, req, smb_dname);

	DEBUG(5, ("create_directory returned %s\n", nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)) {

		if (!use_nt_status()
		    && NT_STATUS_EQUAL(status,
				       NT_STATUS_OBJECT_NAME_COLLISION)) {
			/*
			 * Yes, in the DOS error code case we get a
			 * ERRDOS:ERRnoaccess here. See BASE-SAMBA3ERROR
			 * samba4 torture test.
			 */
			status = NT_STATUS_DOS(ERRDOS, ERRnoaccess);
		}

		reply_nterror(req, status);
		goto out;
	}

	reply_outbuf(req, 0, 0);

	DEBUG(3, ("mkdir %s\n", smb_dname->base_name));
 out:
	TALLOC_FREE(smb_dname);
	END_PROFILE(SMBmkdir);
	return;
}

/****************************************************************************
 Reply to a rmdir.
****************************************************************************/

void reply_rmdir(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_dname = NULL;
	char *directory = NULL;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();
	files_struct *fsp = NULL;
	int info = 0;
	uint32_t ucf_flags = (req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	struct smbd_server_connection *sconn = req->sconn;

	START_PROFILE(SMBrmdir);

	srvstr_get_path_req(ctx, req, &directory, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert(ctx, conn,
				 req->flags2 & FLAGS2_DFS_PATHNAMES,
				 directory,
				 ucf_flags,
				 NULL,
				 &smb_dname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (is_ntfs_stream_smb_fname(smb_dname)) {
		reply_nterror(req, NT_STATUS_NOT_A_DIRECTORY);
		goto out;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,                                   /* conn */
		req,                                    /* req */
		0,                                      /* root_dir_fid */
		smb_dname,                              /* fname */
		DELETE_ACCESS,                          /* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |   /* share_access */
			FILE_SHARE_DELETE),
		FILE_OPEN,                              /* create_disposition*/
		FILE_DIRECTORY_FILE,                    /* create_options */
		FILE_ATTRIBUTE_DIRECTORY,               /* file_attributes */
		0,                                      /* oplock_request */
		NULL,					/* lease */
		0,                                      /* allocation_size */
		0,					/* private_flags */
		NULL,                                   /* sd */
		NULL,                                   /* ea_list */
		&fsp,                                   /* result */
		&info,                                  /* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = can_set_delete_on_close(fsp, FILE_ATTRIBUTE_DIRECTORY);
	if (!NT_STATUS_IS_OK(status)) {
		close_file(req, fsp, ERROR_CLOSE);
		reply_nterror(req, status);
		goto out;
	}

	if (!set_delete_on_close(fsp, true,
			conn->session_info->security_token,
			conn->session_info->unix_token)) {
		close_file(req, fsp, ERROR_CLOSE);
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	status = close_file(req, fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
	} else {
		reply_outbuf(req, 0, 0);
	}

	dptr_closepath(sconn, smb_dname->base_name, req->smbpid);

	DEBUG(3, ("rmdir %s\n", smb_fname_str_dbg(smb_dname)));
 out:
	TALLOC_FREE(smb_dname);
	END_PROFILE(SMBrmdir);
	return;
}

/*******************************************************************
 Resolve wildcards in a filename rename.
********************************************************************/

static bool resolve_wildcards(TALLOC_CTX *ctx,
				const char *name1,
				const char *name2,
				char **pp_newname)
{
	char *name2_copy = NULL;
	char *root1 = NULL;
	char *root2 = NULL;
	char *ext1 = NULL;
	char *ext2 = NULL;
	char *p,*p2, *pname1, *pname2;

	name2_copy = talloc_strdup(ctx, name2);
	if (!name2_copy) {
		return False;
	}

	pname1 = strrchr_m(name1,'/');
	pname2 = strrchr_m(name2_copy,'/');

	if (!pname1 || !pname2) {
		return False;
	}

	/* Truncate the copy of name2 at the last '/' */
	*pname2 = '\0';

	/* Now go past the '/' */
	pname1++;
	pname2++;

	root1 = talloc_strdup(ctx, pname1);
	root2 = talloc_strdup(ctx, pname2);

	if (!root1 || !root2) {
		return False;
	}

	p = strrchr_m(root1,'.');
	if (p) {
		*p = 0;
		ext1 = talloc_strdup(ctx, p+1);
	} else {
		ext1 = talloc_strdup(ctx, "");
	}
	p = strrchr_m(root2,'.');
	if (p) {
		*p = 0;
		ext2 = talloc_strdup(ctx, p+1);
	} else {
		ext2 = talloc_strdup(ctx, "");
	}

	if (!ext1 || !ext2) {
		return False;
	}

	p = root1;
	p2 = root2;
	while (*p2) {
		if (*p2 == '?') {
			/* Hmmm. Should this be mb-aware ? */
			*p2 = *p;
			p2++;
		} else if (*p2 == '*') {
			*p2 = '\0';
			root2 = talloc_asprintf(ctx, "%s%s",
						root2,
						p);
			if (!root2) {
				return False;
			}
			break;
		} else {
			p2++;
		}
		if (*p) {
			p++;
		}
	}

	p = ext1;
	p2 = ext2;
	while (*p2) {
		if (*p2 == '?') {
			/* Hmmm. Should this be mb-aware ? */
			*p2 = *p;
			p2++;
		} else if (*p2 == '*') {
			*p2 = '\0';
			ext2 = talloc_asprintf(ctx, "%s%s",
						ext2,
						p);
			if (!ext2) {
				return False;
			}
			break;
		} else {
			p2++;
		}
		if (*p) {
			p++;
		}
	}

	if (*ext2) {
		*pp_newname = talloc_asprintf(ctx, "%s/%s.%s",
				name2_copy,
				root2,
				ext2);
	} else {
		*pp_newname = talloc_asprintf(ctx, "%s/%s",
				name2_copy,
				root2);
	}

	if (!*pp_newname) {
		return False;
	}

	return True;
}

/****************************************************************************
 Ensure open files have their names updated. Updated to notify other smbd's
 asynchronously.
****************************************************************************/

static void rename_open_files(connection_struct *conn,
			      struct share_mode_lock *lck,
			      struct file_id id,
			      uint32_t orig_name_hash,
			      const struct smb_filename *smb_fname_dst)
{
	files_struct *fsp;
	bool did_rename = False;
	NTSTATUS status;
	uint32_t new_name_hash = 0;

	for(fsp = file_find_di_first(conn->sconn, id); fsp;
	    fsp = file_find_di_next(fsp)) {
		/* fsp_name is a relative path under the fsp. To change this for other
		   sharepaths we need to manipulate relative paths. */
		/* TODO - create the absolute path and manipulate the newname
		   relative to the sharepath. */
		if (!strequal(fsp->conn->connectpath, conn->connectpath)) {
			continue;
		}
		if (fsp->name_hash != orig_name_hash) {
			continue;
		}
		DEBUG(10, ("rename_open_files: renaming file %s "
			   "(file_id %s) from %s -> %s\n", fsp_fnum_dbg(fsp),
			   file_id_string_tos(&fsp->file_id), fsp_str_dbg(fsp),
			   smb_fname_str_dbg(smb_fname_dst)));

		status = fsp_set_smb_fname(fsp, smb_fname_dst);
		if (NT_STATUS_IS_OK(status)) {
			did_rename = True;
			new_name_hash = fsp->name_hash;
		}
	}

	if (!did_rename) {
		DEBUG(10, ("rename_open_files: no open files on file_id %s "
			   "for %s\n", file_id_string_tos(&id),
			   smb_fname_str_dbg(smb_fname_dst)));
	}

	/* Send messages to all smbd's (not ourself) that the name has changed. */
	rename_share_filename(conn->sconn->msg_ctx, lck, id, conn->connectpath,
			      orig_name_hash, new_name_hash,
			      smb_fname_dst);

}

/****************************************************************************
 We need to check if the source path is a parent directory of the destination
 (ie. a rename of /foo/bar/baz -> /foo/bar/baz/bibble/bobble. If so we must
 refuse the rename with a sharing violation. Under UNIX the above call can
 *succeed* if /foo/bar/baz is a symlink to another area in the share. We
 probably need to check that the client is a Windows one before disallowing
 this as a UNIX client (one with UNIX extensions) can know the source is a
 symlink and make this decision intelligently. Found by an excellent bug
 report from <AndyLiebman@aol.com>.
****************************************************************************/

static bool rename_path_prefix_equal(const struct smb_filename *smb_fname_src,
				     const struct smb_filename *smb_fname_dst)
{
	const char *psrc = smb_fname_src->base_name;
	const char *pdst = smb_fname_dst->base_name;
	size_t slen;

	if (psrc[0] == '.' && psrc[1] == '/') {
		psrc += 2;
	}
	if (pdst[0] == '.' && pdst[1] == '/') {
		pdst += 2;
	}
	if ((slen = strlen(psrc)) > strlen(pdst)) {
		return False;
	}
	return ((memcmp(psrc, pdst, slen) == 0) && pdst[slen] == '/');
}

/*
 * Do the notify calls from a rename
 */

static void notify_rename(connection_struct *conn, bool is_dir,
			  const struct smb_filename *smb_fname_src,
			  const struct smb_filename *smb_fname_dst)
{
	char *parent_dir_src = NULL;
	char *parent_dir_dst = NULL;
	uint32_t mask;

	mask = is_dir ? FILE_NOTIFY_CHANGE_DIR_NAME
		: FILE_NOTIFY_CHANGE_FILE_NAME;

	if (!parent_dirname(talloc_tos(), smb_fname_src->base_name,
			    &parent_dir_src, NULL) ||
	    !parent_dirname(talloc_tos(), smb_fname_dst->base_name,
			    &parent_dir_dst, NULL)) {
		goto out;
	}

	if (strcmp(parent_dir_src, parent_dir_dst) == 0) {
		notify_fname(conn, NOTIFY_ACTION_OLD_NAME, mask,
			     smb_fname_src->base_name);
		notify_fname(conn, NOTIFY_ACTION_NEW_NAME, mask,
			     smb_fname_dst->base_name);
	}
	else {
		notify_fname(conn, NOTIFY_ACTION_REMOVED, mask,
			     smb_fname_src->base_name);
		notify_fname(conn, NOTIFY_ACTION_ADDED, mask,
			     smb_fname_dst->base_name);
	}

	/* this is a strange one. w2k3 gives an additional event for
	   CHANGE_ATTRIBUTES and CHANGE_CREATION on the new file when renaming
	   files, but not directories */
	if (!is_dir) {
		notify_fname(conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES
			     |FILE_NOTIFY_CHANGE_CREATION,
			     smb_fname_dst->base_name);
	}
 out:
	TALLOC_FREE(parent_dir_src);
	TALLOC_FREE(parent_dir_dst);
}

/****************************************************************************
 Returns an error if the parent directory for a filename is open in an
 incompatible way.
****************************************************************************/

static NTSTATUS parent_dirname_compatible_open(connection_struct *conn,
					const struct smb_filename *smb_fname_dst_in)
{
	char *parent_dir = NULL;
	struct smb_filename smb_fname_parent;
	struct file_id id;
	files_struct *fsp = NULL;
	int ret;

	if (!parent_dirname(talloc_tos(), smb_fname_dst_in->base_name,
			&parent_dir, NULL)) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCT(smb_fname_parent);
	smb_fname_parent.base_name = parent_dir;

	ret = SMB_VFS_LSTAT(conn, &smb_fname_parent);
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	/*
	 * We're only checking on this smbd here, mostly good
	 * enough.. and will pass tests.
	 */

	id = vfs_file_id_from_sbuf(conn, &smb_fname_parent.st);
	for (fsp = file_find_di_first(conn->sconn, id); fsp;
			fsp = file_find_di_next(fsp)) {
		if (fsp->access_mask & DELETE_ACCESS) {
			return NT_STATUS_SHARING_VIOLATION;
                }
        }
	return NT_STATUS_OK;
}

/****************************************************************************
 Rename an open file - given an fsp.
****************************************************************************/

NTSTATUS rename_internals_fsp(connection_struct *conn,
			files_struct *fsp,
			const struct smb_filename *smb_fname_dst_in,
			uint32_t attrs,
			bool replace_if_exists)
{
	TALLOC_CTX *ctx = talloc_tos();
	struct smb_filename *smb_fname_dst = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct share_mode_lock *lck = NULL;
	bool dst_exists, old_is_stream, new_is_stream;

	status = check_name(conn, smb_fname_dst_in->base_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = parent_dirname_compatible_open(conn, smb_fname_dst_in);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Make a copy of the dst smb_fname structs */

	smb_fname_dst = cp_smb_filename(ctx, smb_fname_dst_in);
	if (smb_fname_dst == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	/*
	 * Check for special case with case preserving and not
	 * case sensitive. If the new last component differs from the original
	 * last component only by case, then we should allow
	 * the rename (user is trying to change the case of the
	 * filename).
	 */
	if (!conn->case_sensitive && conn->case_preserve &&
	    strequal(fsp->fsp_name->base_name, smb_fname_dst->base_name) &&
	    strequal(fsp->fsp_name->stream_name, smb_fname_dst->stream_name)) {
		char *fname_dst_parent = NULL;
		const char *fname_dst_lcomp = NULL;
		char *orig_lcomp_path = NULL;
		char *orig_lcomp_stream = NULL;
		bool ok = true;

		/*
		 * Split off the last component of the processed
		 * destination name. We will compare this to
		 * the split components of smb_fname_dst->original_lcomp.
		 */
		if (!parent_dirname(ctx,
				smb_fname_dst->base_name,
				&fname_dst_parent,
				&fname_dst_lcomp)) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		/*
		 * The original_lcomp component contains
		 * the last_component of the path + stream
		 * name (if a stream exists).
		 *
		 * Split off the stream name so we
		 * can check them separately.
		 */

		if (fsp->posix_flags & FSP_POSIX_FLAGS_PATHNAMES) {
			/* POSIX - no stream component. */
			orig_lcomp_path = talloc_strdup(ctx,
						smb_fname_dst->original_lcomp);
			if (orig_lcomp_path == NULL) {
				ok = false;
			}
		} else {
			ok = split_stream_filename(ctx,
					smb_fname_dst->original_lcomp,
					&orig_lcomp_path,
					&orig_lcomp_stream);
		}

		if (!ok) {
			TALLOC_FREE(fname_dst_parent);
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		/* If the base names only differ by case, use original. */
		if(!strcsequal(fname_dst_lcomp, orig_lcomp_path)) {
			char *tmp;
			/*
			 * Replace the modified last component with the
			 * original.
			 */
			if (!ISDOT(fname_dst_parent)) {
				tmp = talloc_asprintf(smb_fname_dst,
					"%s/%s",
					fname_dst_parent,
					orig_lcomp_path);
			} else {
				tmp = talloc_strdup(smb_fname_dst,
					orig_lcomp_path);
			}
			if (tmp == NULL) {
				status = NT_STATUS_NO_MEMORY;
				TALLOC_FREE(fname_dst_parent);
				TALLOC_FREE(orig_lcomp_path);
				TALLOC_FREE(orig_lcomp_stream);
				goto out;
			}
			TALLOC_FREE(smb_fname_dst->base_name);
			smb_fname_dst->base_name = tmp;
		}

		/* If the stream_names only differ by case, use original. */
		if(!strcsequal(smb_fname_dst->stream_name,
			       orig_lcomp_stream)) {
			/* Use the original stream. */
			char *tmp = talloc_strdup(smb_fname_dst,
					    orig_lcomp_stream);
			if (tmp == NULL) {
				status = NT_STATUS_NO_MEMORY;
				TALLOC_FREE(fname_dst_parent);
				TALLOC_FREE(orig_lcomp_path);
				TALLOC_FREE(orig_lcomp_stream);
				goto out;
			}
			TALLOC_FREE(smb_fname_dst->stream_name);
			smb_fname_dst->stream_name = tmp;
		}
		TALLOC_FREE(fname_dst_parent);
		TALLOC_FREE(orig_lcomp_path);
		TALLOC_FREE(orig_lcomp_stream);
	}

	/*
	 * If the src and dest names are identical - including case,
	 * don't do the rename, just return success.
	 */

	if (strcsequal(fsp->fsp_name->base_name, smb_fname_dst->base_name) &&
	    strcsequal(fsp->fsp_name->stream_name,
		       smb_fname_dst->stream_name)) {
		DEBUG(3, ("rename_internals_fsp: identical names in rename %s "
			  "- returning success\n",
			  smb_fname_str_dbg(smb_fname_dst)));
		status = NT_STATUS_OK;
		goto out;
	}

	old_is_stream = is_ntfs_stream_smb_fname(fsp->fsp_name);
	new_is_stream = is_ntfs_stream_smb_fname(smb_fname_dst);

	/* Return the correct error code if both names aren't streams. */
	if (!old_is_stream && new_is_stream) {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto out;
	}

	if (old_is_stream && !new_is_stream) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	dst_exists = SMB_VFS_STAT(conn, smb_fname_dst) == 0;

	if(!replace_if_exists && dst_exists) {
		DEBUG(3, ("rename_internals_fsp: dest exists doing rename "
			  "%s -> %s\n", smb_fname_str_dbg(fsp->fsp_name),
			  smb_fname_str_dbg(smb_fname_dst)));
		status = NT_STATUS_OBJECT_NAME_COLLISION;
		goto out;
	}

	if (dst_exists) {
		struct file_id fileid = vfs_file_id_from_sbuf(conn,
		    &smb_fname_dst->st);
		files_struct *dst_fsp = file_find_di_first(conn->sconn,
							   fileid);
		/* The file can be open when renaming a stream */
		if (dst_fsp && !new_is_stream) {
			DEBUG(3, ("rename_internals_fsp: Target file open\n"));
			status = NT_STATUS_ACCESS_DENIED;
			goto out;
		}
	}

	/* Ensure we have a valid stat struct for the source. */
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = can_rename(conn, fsp, attrs);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("rename_internals_fsp: Error %s rename %s -> %s\n",
			  nt_errstr(status), smb_fname_str_dbg(fsp->fsp_name),
			  smb_fname_str_dbg(smb_fname_dst)));
		if (NT_STATUS_EQUAL(status,NT_STATUS_SHARING_VIOLATION))
			status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	if (rename_path_prefix_equal(fsp->fsp_name, smb_fname_dst)) {
		status = NT_STATUS_ACCESS_DENIED;
	}

	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);

	/*
	 * We have the file open ourselves, so not being able to get the
	 * corresponding share mode lock is a fatal error.
	 */

	SMB_ASSERT(lck != NULL);

	if(SMB_VFS_RENAME(conn, fsp->fsp_name, smb_fname_dst) == 0) {
		uint32_t create_options = fsp->fh->private_options;

		DEBUG(3, ("rename_internals_fsp: succeeded doing rename on "
			  "%s -> %s\n", smb_fname_str_dbg(fsp->fsp_name),
			  smb_fname_str_dbg(smb_fname_dst)));

		if (!fsp->is_directory &&
		    !(fsp->posix_flags & FSP_POSIX_FLAGS_PATHNAMES) &&
		    (lp_map_archive(SNUM(conn)) ||
		    lp_store_dos_attributes(SNUM(conn)))) {
			/* We must set the archive bit on the newly
			   renamed file. */
			if (SMB_VFS_STAT(conn, smb_fname_dst) == 0) {
				uint32_t old_dosmode = dos_mode(conn,
							smb_fname_dst);
				file_set_dosmode(conn,
					smb_fname_dst,
					old_dosmode | FILE_ATTRIBUTE_ARCHIVE,
					NULL,
					true);
			}
		}

		notify_rename(conn, fsp->is_directory, fsp->fsp_name,
			      smb_fname_dst);

		rename_open_files(conn, lck, fsp->file_id, fsp->name_hash,
				  smb_fname_dst);

		/*
		 * A rename acts as a new file create w.r.t. allowing an initial delete
		 * on close, probably because in Windows there is a new handle to the
		 * new file. If initial delete on close was requested but not
		 * originally set, we need to set it here. This is probably not 100% correct,
		 * but will work for the CIFSFS client which in non-posix mode
		 * depends on these semantics. JRA.
		 */

		if (create_options & FILE_DELETE_ON_CLOSE) {
			status = can_set_delete_on_close(fsp, 0);

			if (NT_STATUS_IS_OK(status)) {
				/* Note that here we set the *inital* delete on close flag,
				 * not the regular one. The magic gets handled in close. */
				fsp->initial_delete_on_close = True;
			}
		}
		TALLOC_FREE(lck);
		status = NT_STATUS_OK;
		goto out;
	}

	TALLOC_FREE(lck);

	if (errno == ENOTDIR || errno == EISDIR) {
		status = NT_STATUS_OBJECT_NAME_COLLISION;
	} else {
		status = map_nt_error_from_unix(errno);
	}

	DEBUG(3, ("rename_internals_fsp: Error %s rename %s -> %s\n",
		  nt_errstr(status), smb_fname_str_dbg(fsp->fsp_name),
		  smb_fname_str_dbg(smb_fname_dst)));

 out:
	TALLOC_FREE(smb_fname_dst);

	return status;
}

/****************************************************************************
 The guts of the rename command, split out so it may be called by the NT SMB
 code.
****************************************************************************/

NTSTATUS rename_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			uint32_t attrs,
			bool replace_if_exists,
			bool src_has_wild,
			bool dest_has_wild,
			uint32_t access_mask)
{
	char *fname_src_dir = NULL;
	struct smb_filename *smb_fname_src_dir = NULL;
	char *fname_src_mask = NULL;
	int count=0;
	NTSTATUS status = NT_STATUS_OK;
	struct smb_Dir *dir_hnd = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	long offset = 0;
	int create_options = 0;
	bool posix_pathnames = (req != NULL && req->posix_pathnames);
	int rc;

	/*
	 * Split the old name into directory and last component
	 * strings. Note that unix_convert may have stripped off a
	 * leading ./ from both name and newname if the rename is
	 * at the root of the share. We need to make sure either both
	 * name and newname contain a / character or neither of them do
	 * as this is checked in resolve_wildcards().
	 */

	/* Split up the directory from the filename/mask. */
	status = split_fname_dir_mask(ctx, smb_fname_src->base_name,
				      &fname_src_dir, &fname_src_mask);
	if (!NT_STATUS_IS_OK(status)) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!VALID_STAT(smb_fname_src->st) &&
	    mangle_is_mangled(fname_src_mask, conn->params)) {
		char *new_mask = NULL;
		mangle_lookup_name_from_8_3(ctx, fname_src_mask, &new_mask,
					    conn->params);
		if (new_mask) {
			TALLOC_FREE(fname_src_mask);
			fname_src_mask = new_mask;
		}
	}

	if (!src_has_wild) {
		files_struct *fsp;

		/*
		 * Only one file needs to be renamed. Append the mask back
		 * onto the directory.
		 */
		TALLOC_FREE(smb_fname_src->base_name);
		if (ISDOT(fname_src_dir)) {
			/* Ensure we use canonical names on open. */
			smb_fname_src->base_name = talloc_asprintf(smb_fname_src,
							"%s",
							fname_src_mask);
		} else {
			smb_fname_src->base_name = talloc_asprintf(smb_fname_src,
							"%s/%s",
							fname_src_dir,
							fname_src_mask);
		}
		if (!smb_fname_src->base_name) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		DEBUG(3, ("rename_internals: case_sensitive = %d, "
			  "case_preserve = %d, short case preserve = %d, "
			  "directory = %s, newname = %s, "
			  "last_component_dest = %s\n",
			  conn->case_sensitive, conn->case_preserve,
			  conn->short_case_preserve,
			  smb_fname_str_dbg(smb_fname_src),
			  smb_fname_str_dbg(smb_fname_dst),
			  smb_fname_dst->original_lcomp));

		/* The dest name still may have wildcards. */
		if (dest_has_wild) {
			char *fname_dst_mod = NULL;
			if (!resolve_wildcards(smb_fname_dst,
					       smb_fname_src->base_name,
					       smb_fname_dst->base_name,
					       &fname_dst_mod)) {
				DEBUG(6, ("rename_internals: resolve_wildcards "
					  "%s %s failed\n",
					  smb_fname_src->base_name,
					  smb_fname_dst->base_name));
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
			TALLOC_FREE(smb_fname_dst->base_name);
			smb_fname_dst->base_name = fname_dst_mod;
		}

		ZERO_STRUCT(smb_fname_src->st);
		if (posix_pathnames) {
			rc = SMB_VFS_LSTAT(conn, smb_fname_src);
		} else {
			rc = SMB_VFS_STAT(conn, smb_fname_src);
		}
		if (rc == -1) {
			status = map_nt_error_from_unix_common(errno);
			goto out;
		}

		if (S_ISDIR(smb_fname_src->st.st_ex_mode)) {
			create_options |= FILE_DIRECTORY_FILE;
		}

		status = SMB_VFS_CREATE_FILE(
			conn,				/* conn */
			req,				/* req */
			0,				/* root_dir_fid */
			smb_fname_src,			/* fname */
			access_mask,			/* access_mask */
			(FILE_SHARE_READ |		/* share_access */
			    FILE_SHARE_WRITE),
			FILE_OPEN,			/* create_disposition*/
			create_options,			/* create_options */
			posix_pathnames ? FILE_FLAG_POSIX_SEMANTICS|0777 : 0, /* file_attributes */
			0,				/* oplock_request */
			NULL,				/* lease */
			0,				/* allocation_size */
			0,				/* private_flags */
			NULL,				/* sd */
			NULL,				/* ea_list */
			&fsp,				/* result */
			NULL,				/* pinfo */
			NULL, NULL);			/* create context */

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not open rename source %s: %s\n",
				  smb_fname_str_dbg(smb_fname_src),
				  nt_errstr(status)));
			goto out;
		}

		status = rename_internals_fsp(conn, fsp, smb_fname_dst,
					      attrs, replace_if_exists);

		close_file(req, fsp, NORMAL_CLOSE);

		DEBUG(3, ("rename_internals: Error %s rename %s -> %s\n",
			  nt_errstr(status), smb_fname_str_dbg(smb_fname_src),
			  smb_fname_str_dbg(smb_fname_dst)));

		goto out;
	}

	/*
	 * Wildcards - process each file that matches.
	 */
	if (strequal(fname_src_mask, "????????.???")) {
		TALLOC_FREE(fname_src_mask);
		fname_src_mask = talloc_strdup(ctx, "*");
		if (!fname_src_mask) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	status = check_name(conn, fname_src_dir);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	smb_fname_src_dir = synthetic_smb_fname(talloc_tos(),
				fname_src_dir,
				NULL,
				NULL,
				smb_fname_src->flags);
	if (smb_fname_src_dir == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	dir_hnd = OpenDir(talloc_tos(), conn, smb_fname_src_dir, fname_src_mask,
			  attrs);
	if (dir_hnd == NULL) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	status = NT_STATUS_NO_SUCH_FILE;
	/*
	 * Was status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	 * - gentest fix. JRA
	 */

	while ((dname = ReadDirName(dir_hnd, &offset, &smb_fname_src->st,
				    &talloced))) {
		files_struct *fsp = NULL;
		char *destname = NULL;
		bool sysdir_entry = False;

		/* Quick check for "." and ".." */
		if (ISDOT(dname) || ISDOTDOT(dname)) {
			if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
				sysdir_entry = True;
			} else {
				TALLOC_FREE(talloced);
				continue;
			}
		}

		if (!is_visible_file(conn, fname_src_dir, dname,
				     &smb_fname_src->st, false)) {
			TALLOC_FREE(talloced);
			continue;
		}

		if(!mask_match(dname, fname_src_mask, conn->case_sensitive)) {
			TALLOC_FREE(talloced);
			continue;
		}

		if (sysdir_entry) {
			status = NT_STATUS_OBJECT_NAME_INVALID;
			break;
		}

		TALLOC_FREE(smb_fname_src->base_name);
		if (ISDOT(fname_src_dir)) {
			/* Ensure we use canonical names on open. */
			smb_fname_src->base_name = talloc_asprintf(smb_fname_src,
							"%s",
							dname);
		} else {
			smb_fname_src->base_name = talloc_asprintf(smb_fname_src,
							"%s/%s",
							fname_src_dir,
							dname);
		}
		if (!smb_fname_src->base_name) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		if (!resolve_wildcards(ctx, smb_fname_src->base_name,
				       smb_fname_dst->base_name,
				       &destname)) {
			DEBUG(6, ("resolve_wildcards %s %s failed\n",
				  smb_fname_src->base_name, destname));
			TALLOC_FREE(talloced);
			continue;
		}
		if (!destname) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		TALLOC_FREE(smb_fname_dst->base_name);
		smb_fname_dst->base_name = destname;

		ZERO_STRUCT(smb_fname_src->st);
		if (posix_pathnames) {
			SMB_VFS_LSTAT(conn, smb_fname_src);
		} else {
			SMB_VFS_STAT(conn, smb_fname_src);
		}

		create_options = 0;

		if (S_ISDIR(smb_fname_src->st.st_ex_mode)) {
			create_options |= FILE_DIRECTORY_FILE;
		}

		status = SMB_VFS_CREATE_FILE(
			conn,				/* conn */
			req,				/* req */
			0,				/* root_dir_fid */
			smb_fname_src,			/* fname */
			access_mask,			/* access_mask */
			(FILE_SHARE_READ |		/* share_access */
			    FILE_SHARE_WRITE),
			FILE_OPEN,			/* create_disposition*/
			create_options,			/* create_options */
			posix_pathnames ? FILE_FLAG_POSIX_SEMANTICS|0777 : 0, /* file_attributes */
			0,				/* oplock_request */
			NULL,				/* lease */
			0,				/* allocation_size */
			0,				/* private_flags */
			NULL,				/* sd */
			NULL,				/* ea_list */
			&fsp,				/* result */
			NULL,				/* pinfo */
			NULL, NULL);			/* create context */

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("rename_internals: SMB_VFS_CREATE_FILE "
				 "returned %s rename %s -> %s\n",
				 nt_errstr(status),
				 smb_fname_str_dbg(smb_fname_src),
				 smb_fname_str_dbg(smb_fname_dst)));
			break;
		}

		smb_fname_dst->original_lcomp = talloc_strdup(smb_fname_dst,
							      dname);
		if (!smb_fname_dst->original_lcomp) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		status = rename_internals_fsp(conn, fsp, smb_fname_dst,
					      attrs, replace_if_exists);

		close_file(req, fsp, NORMAL_CLOSE);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("rename_internals_fsp returned %s for "
				  "rename %s -> %s\n", nt_errstr(status),
				  smb_fname_str_dbg(smb_fname_src),
				  smb_fname_str_dbg(smb_fname_dst)));
			break;
		}

		count++;

		DEBUG(3,("rename_internals: doing rename on %s -> "
			 "%s\n", smb_fname_str_dbg(smb_fname_src),
			 smb_fname_str_dbg(smb_fname_src)));
		TALLOC_FREE(talloced);
	}
	TALLOC_FREE(dir_hnd);

	if (count == 0 && NT_STATUS_IS_OK(status) && errno != 0) {
		status = map_nt_error_from_unix(errno);
	}

 out:
	TALLOC_FREE(talloced);
	TALLOC_FREE(smb_fname_src_dir);
	TALLOC_FREE(fname_src_dir);
	TALLOC_FREE(fname_src_mask);
	return status;
}

/****************************************************************************
 Reply to a mv.
****************************************************************************/

void reply_mv(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	char *newname = NULL;
	const char *p;
	uint32_t attrs;
	NTSTATUS status;
	bool src_has_wcard = False;
	bool dest_has_wcard = False;
	TALLOC_CTX *ctx = talloc_tos();
	struct smb_filename *smb_fname_src = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	uint32_t src_ucf_flags = (req->posix_pathnames ?
		(UCF_UNIX_NAME_LOOKUP|UCF_POSIX_PATHNAMES) :
		UCF_COND_ALLOW_WCARD_LCOMP);
	uint32_t dst_ucf_flags = UCF_SAVE_LCOMP |
		(req->posix_pathnames ? UCF_POSIX_PATHNAMES :
		 UCF_COND_ALLOW_WCARD_LCOMP);
	bool stream_rename = false;

	START_PROFILE(SMBmv);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	attrs = SVAL(req->vwv+0, 0);

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req_wcard(ctx, req, &name, p, STR_TERMINATE,
				       &status, &src_has_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	p++;
	p += srvstr_get_path_req_wcard(ctx, req, &newname, p, STR_TERMINATE,
				       &status, &dest_has_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!req->posix_pathnames) {
		/* The newname must begin with a ':' if the
		   name contains a ':'. */
		if (strchr_m(name, ':')) {
			if (newname[0] != ':') {
				reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
				goto out;
			}
			stream_rename = true;
		}
        }

	status = filename_convert(ctx,
				  conn,
				  req->flags2 & FLAGS2_DFS_PATHNAMES,
				  name,
				  src_ucf_flags,
				  &src_has_wcard,
				  &smb_fname_src);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert(ctx,
				  conn,
				  req->flags2 & FLAGS2_DFS_PATHNAMES,
				  newname,
				  dst_ucf_flags,
				  &dest_has_wcard,
				  &smb_fname_dst);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (stream_rename) {
		/* smb_fname_dst->base_name must be the same as
		   smb_fname_src->base_name. */
		TALLOC_FREE(smb_fname_dst->base_name);
		smb_fname_dst->base_name = talloc_strdup(smb_fname_dst,
						smb_fname_src->base_name);
		if (!smb_fname_dst->base_name) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}
	}

	DEBUG(3,("reply_mv : %s -> %s\n", smb_fname_str_dbg(smb_fname_src),
		 smb_fname_str_dbg(smb_fname_dst)));

	status = rename_internals(ctx, conn, req, smb_fname_src, smb_fname_dst,
				  attrs, False, src_has_wcard, dest_has_wcard,
				  DELETE_ACCESS);
	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	reply_outbuf(req, 0, 0);
 out:
	TALLOC_FREE(smb_fname_src);
	TALLOC_FREE(smb_fname_dst);
	END_PROFILE(SMBmv);
	return;
}

/*******************************************************************
 Copy a file as part of a reply_copy.
******************************************************************/

/*
 * TODO: check error codes on all callers
 */

NTSTATUS copy_file(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			int ofun,
			int count,
			bool target_is_directory)
{
	struct smb_filename *smb_fname_dst_tmp = NULL;
	off_t ret=-1;
	files_struct *fsp1,*fsp2;
	uint32_t dosattrs;
	uint32_t new_create_disposition;
	NTSTATUS status;


	smb_fname_dst_tmp = cp_smb_filename(ctx, smb_fname_dst);
	if (smb_fname_dst_tmp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * If the target is a directory, extract the last component from the
	 * src filename and append it to the dst filename
	 */
	if (target_is_directory) {
		const char *p;

		/* dest/target can't be a stream if it's a directory. */
		SMB_ASSERT(smb_fname_dst->stream_name == NULL);

		p = strrchr_m(smb_fname_src->base_name,'/');
		if (p) {
			p++;
		} else {
			p = smb_fname_src->base_name;
		}
		smb_fname_dst_tmp->base_name =
		    talloc_asprintf_append(smb_fname_dst_tmp->base_name, "/%s",
					   p);
		if (!smb_fname_dst_tmp->base_name) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	status = vfs_file_exist(conn, smb_fname_src);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (!target_is_directory && count) {
		new_create_disposition = FILE_OPEN;
	} else {
		if (!map_open_params_to_ntcreate(smb_fname_dst_tmp->base_name,
						 0, ofun,
						 NULL, NULL,
						 &new_create_disposition,
						 NULL,
						 NULL)) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	}

	/* Open the src file for reading. */
	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		0,					/* root_dir_fid */
		smb_fname_src,	       			/* fname */
		FILE_GENERIC_READ,			/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp1,					/* result */
		NULL,					/* psbuf */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	dosattrs = dos_mode(conn, smb_fname_src);

	if (SMB_VFS_STAT(conn, smb_fname_dst_tmp) == -1) {
		ZERO_STRUCTP(&smb_fname_dst_tmp->st);
	}

	/* Open the dst file for writing. */
	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		0,					/* root_dir_fid */
		smb_fname_dst,				/* fname */
		FILE_GENERIC_WRITE,			/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
		new_create_disposition,			/* create_disposition*/
		0,					/* create_options */
		dosattrs,				/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp2,					/* result */
		NULL,					/* psbuf */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		close_file(NULL, fsp1, ERROR_CLOSE);
		goto out;
	}

	if (ofun & OPENX_FILE_EXISTS_OPEN) {
		ret = SMB_VFS_LSEEK(fsp2, 0, SEEK_END);
		if (ret == -1) {
			DEBUG(0, ("error - vfs lseek returned error %s\n",
				strerror(errno)));
			status = map_nt_error_from_unix(errno);
			close_file(NULL, fsp1, ERROR_CLOSE);
			close_file(NULL, fsp2, ERROR_CLOSE);
			goto out;
		}
	}

	/* Do the actual copy. */
	if (smb_fname_src->st.st_ex_size) {
		ret = vfs_transfer_file(fsp1, fsp2, smb_fname_src->st.st_ex_size);
	} else {
		ret = 0;
	}

	close_file(NULL, fsp1, NORMAL_CLOSE);

	/* Ensure the modtime is set correctly on the destination file. */
	set_close_write_time(fsp2, smb_fname_src->st.st_ex_mtime);

	/*
	 * As we are opening fsp1 read-only we only expect
	 * an error on close on fsp2 if we are out of space.
	 * Thus we don't look at the error return from the
	 * close of fsp1.
	 */
	status = close_file(NULL, fsp2, NORMAL_CLOSE);

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (ret != (off_t)smb_fname_src->st.st_ex_size) {
		status = NT_STATUS_DISK_FULL;
		goto out;
	}

	status = NT_STATUS_OK;

 out:
	TALLOC_FREE(smb_fname_dst_tmp);
	return status;
}

/****************************************************************************
 Reply to a file copy.
****************************************************************************/

void reply_copy(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname_src = NULL;
	struct smb_filename *smb_fname_src_dir = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	char *fname_src = NULL;
	char *fname_dst = NULL;
	char *fname_src_mask = NULL;
	char *fname_src_dir = NULL;
	const char *p;
	int count=0;
	int error = ERRnoaccess;
	int tid2;
	int ofun;
	int flags;
	bool target_is_directory=False;
	bool source_has_wild = False;
	bool dest_has_wild = False;
	NTSTATUS status;
	uint32_t ucf_flags_src = UCF_COND_ALLOW_WCARD_LCOMP |
		(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	uint32_t ucf_flags_dst = UCF_COND_ALLOW_WCARD_LCOMP |
		(req->posix_pathnames ? UCF_POSIX_PATHNAMES : 0);
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcopy);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	tid2 = SVAL(req->vwv+0, 0);
	ofun = SVAL(req->vwv+1, 0);
	flags = SVAL(req->vwv+2, 0);

	p = (const char *)req->buf;
	p += srvstr_get_path_req_wcard(ctx, req, &fname_src, p, STR_TERMINATE,
				       &status, &source_has_wild);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	p += srvstr_get_path_req_wcard(ctx, req, &fname_dst, p, STR_TERMINATE,
				       &status, &dest_has_wild);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	DEBUG(3,("reply_copy : %s -> %s\n", fname_src, fname_dst));

	if (tid2 != conn->cnum) {
		/* can't currently handle inter share copies XXXX */
		DEBUG(3,("Rejecting inter-share copy\n"));
		reply_nterror(req, NT_STATUS_BAD_DEVICE_TYPE);
		goto out;
	}

	status = filename_convert(ctx, conn,
				  req->flags2 & FLAGS2_DFS_PATHNAMES,
				  fname_src,
				  ucf_flags_src,
				  &source_has_wild,
				  &smb_fname_src);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert(ctx, conn,
				  req->flags2 & FLAGS2_DFS_PATHNAMES,
				  fname_dst,
				  ucf_flags_dst,
				  &dest_has_wild,
				  &smb_fname_dst);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	target_is_directory = VALID_STAT_OF_DIR(smb_fname_dst->st);

	if ((flags&1) && target_is_directory) {
		reply_nterror(req, NT_STATUS_NO_SUCH_FILE);
		goto out;
	}

	if ((flags&2) && !target_is_directory) {
		reply_nterror(req, NT_STATUS_OBJECT_PATH_NOT_FOUND);
		goto out;
	}

	if ((flags&(1<<5)) && VALID_STAT_OF_DIR(smb_fname_src->st)) {
		/* wants a tree copy! XXXX */
		DEBUG(3,("Rejecting tree copy\n"));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	/* Split up the directory from the filename/mask. */
	status = split_fname_dir_mask(ctx, smb_fname_src->base_name,
				      &fname_src_dir, &fname_src_mask);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */
	if (!VALID_STAT(smb_fname_src->st) &&
	    mangle_is_mangled(fname_src_mask, conn->params)) {
		char *new_mask = NULL;
		mangle_lookup_name_from_8_3(ctx, fname_src_mask,
					    &new_mask, conn->params);

		/* Use demangled name if one was successfully found. */
		if (new_mask) {
			TALLOC_FREE(fname_src_mask);
			fname_src_mask = new_mask;
		}
	}

	if (!source_has_wild) {

		/*
		 * Only one file needs to be copied. Append the mask back onto
		 * the directory.
		 */
		TALLOC_FREE(smb_fname_src->base_name);
		if (ISDOT(fname_src_dir)) {
			/* Ensure we use canonical names on open. */
			smb_fname_src->base_name = talloc_asprintf(smb_fname_src,
							"%s",
							fname_src_mask);
		} else {
			smb_fname_src->base_name = talloc_asprintf(smb_fname_src,
							"%s/%s",
							fname_src_dir,
							fname_src_mask);
		}
		if (!smb_fname_src->base_name) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		if (dest_has_wild) {
			char *fname_dst_mod = NULL;
			if (!resolve_wildcards(smb_fname_dst,
					       smb_fname_src->base_name,
					       smb_fname_dst->base_name,
					       &fname_dst_mod)) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}
			TALLOC_FREE(smb_fname_dst->base_name);
			smb_fname_dst->base_name = fname_dst_mod;
		}

		status = check_name(conn, smb_fname_src->base_name);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}

		status = check_name(conn, smb_fname_dst->base_name);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}

		status = copy_file(ctx, conn, smb_fname_src, smb_fname_dst,
				   ofun, count, target_is_directory);

		if(!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		} else {
			count++;
		}
	} else {
		struct smb_Dir *dir_hnd = NULL;
		const char *dname = NULL;
		char *talloced = NULL;
		long offset = 0;

		/*
		 * There is a wildcard that requires us to actually read the
		 * src dir and copy each file matching the mask to the dst.
		 * Right now streams won't be copied, but this could
		 * presumably be added with a nested loop for reach dir entry.
		 */
		SMB_ASSERT(!smb_fname_src->stream_name);
		SMB_ASSERT(!smb_fname_dst->stream_name);

		smb_fname_src->stream_name = NULL;
		smb_fname_dst->stream_name = NULL;

		if (strequal(fname_src_mask,"????????.???")) {
			TALLOC_FREE(fname_src_mask);
			fname_src_mask = talloc_strdup(ctx, "*");
			if (!fname_src_mask) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}
		}

		status = check_name(conn, fname_src_dir);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}

		smb_fname_src_dir = synthetic_smb_fname(talloc_tos(),
					fname_src_dir,
					NULL,
					NULL,
					smb_fname_src->flags);
		if (smb_fname_src_dir == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		dir_hnd = OpenDir(ctx,
				conn,
				smb_fname_src_dir,
				fname_src_mask,
				0);
		if (dir_hnd == NULL) {
			status = map_nt_error_from_unix(errno);
			reply_nterror(req, status);
			goto out;
		}

		error = ERRbadfile;

		/* Iterate over the src dir copying each entry to the dst. */
		while ((dname = ReadDirName(dir_hnd, &offset,
					    &smb_fname_src->st, &talloced))) {
			char *destname = NULL;

			if (ISDOT(dname) || ISDOTDOT(dname)) {
				TALLOC_FREE(talloced);
				continue;
			}

			if (!is_visible_file(conn, fname_src_dir, dname,
					     &smb_fname_src->st, false)) {
				TALLOC_FREE(talloced);
				continue;
			}

			if(!mask_match(dname, fname_src_mask,
				       conn->case_sensitive)) {
				TALLOC_FREE(talloced);
				continue;
			}

			error = ERRnoaccess;

			/* Get the src smb_fname struct setup. */
			TALLOC_FREE(smb_fname_src->base_name);
			if (ISDOT(fname_src_dir)) {
				/* Ensure we use canonical names on open. */
				smb_fname_src->base_name =
					talloc_asprintf(smb_fname_src, "%s",
						dname);
			} else {
				smb_fname_src->base_name =
					talloc_asprintf(smb_fname_src, "%s/%s",
						fname_src_dir, dname);
			}

			if (!smb_fname_src->base_name) {
				TALLOC_FREE(dir_hnd);
				TALLOC_FREE(talloced);
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}

			if (!resolve_wildcards(ctx, smb_fname_src->base_name,
					       smb_fname_dst->base_name,
					       &destname)) {
				TALLOC_FREE(talloced);
				continue;
			}
			if (!destname) {
				TALLOC_FREE(dir_hnd);
				TALLOC_FREE(talloced);
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}

			TALLOC_FREE(smb_fname_dst->base_name);
			smb_fname_dst->base_name = destname;

			status = check_name(conn, smb_fname_src->base_name);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(dir_hnd);
				TALLOC_FREE(talloced);
				reply_nterror(req, status);
				goto out;
			}

			status = check_name(conn, smb_fname_dst->base_name);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(dir_hnd);
				TALLOC_FREE(talloced);
				reply_nterror(req, status);
				goto out;
			}

			DEBUG(3,("reply_copy : doing copy on %s -> %s\n",
				smb_fname_src->base_name,
				smb_fname_dst->base_name));

			status = copy_file(ctx, conn, smb_fname_src,
					   smb_fname_dst, ofun,	count,
					   target_is_directory);
			if (NT_STATUS_IS_OK(status)) {
				count++;
			}

			TALLOC_FREE(talloced);
		}
		TALLOC_FREE(dir_hnd);
	}

	if (count == 0) {
		reply_nterror(req, dos_to_ntstatus(ERRDOS, error));
		goto out;
	}

	reply_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,count);
 out:
	TALLOC_FREE(smb_fname_src);
	TALLOC_FREE(smb_fname_src_dir);
	TALLOC_FREE(smb_fname_dst);
	TALLOC_FREE(fname_src);
	TALLOC_FREE(fname_dst);
	TALLOC_FREE(fname_src_mask);
	TALLOC_FREE(fname_src_dir);

	END_PROFILE(SMBcopy);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Get a lock pid, dealing with large count requests.
****************************************************************************/

uint64_t get_lock_pid(const uint8_t *data, int data_offset,
		    bool large_file_format)
{
	if(!large_file_format)
		return (uint64_t)SVAL(data,SMB_LPID_OFFSET(data_offset));
	else
		return (uint64_t)SVAL(data,SMB_LARGE_LPID_OFFSET(data_offset));
}

/****************************************************************************
 Get a lock count, dealing with large count requests.
****************************************************************************/

uint64_t get_lock_count(const uint8_t *data, int data_offset,
			bool large_file_format)
{
	uint64_t count = 0;

	if(!large_file_format) {
		count = (uint64_t)IVAL(data,SMB_LKLEN_OFFSET(data_offset));
	} else {
		/*
		 * No BVAL, this is reversed!
		 */
		count = (((uint64_t) IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset))) << 32) |
			((uint64_t) IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)));
	}

	return count;
}

/****************************************************************************
 Get a lock offset, dealing with large offset requests.
****************************************************************************/

uint64_t get_lock_offset(const uint8_t *data, int data_offset,
			 bool large_file_format)
{
	uint64_t offset = 0;

	if(!large_file_format) {
		offset = (uint64_t)IVAL(data,SMB_LKOFF_OFFSET(data_offset));
	} else {
		/*
		 * No BVAL, this is reversed!
		 */
		offset = (((uint64_t) IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset))) << 32) |
				((uint64_t) IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset)));
	}

	return offset;
}

NTSTATUS smbd_do_locking(struct smb_request *req,
			 files_struct *fsp,
			 uint8_t type,
			 int32_t timeout,
			 uint16_t num_locks,
			 struct smbd_lock_element *locks,
			 bool *async)
{
	connection_struct *conn = req->conn;
	int i;
	NTSTATUS status = NT_STATUS_OK;

	*async = false;

	/* Setup the timeout in seconds. */

	if (!lp_blocking_locks(SNUM(conn))) {
		timeout = 0;
	}

	for(i = 0; i < (int)num_locks; i++) {
		struct smbd_lock_element *e = &locks[i];

		DEBUG(10,("smbd_do_locking: lock start=%.0f, len=%.0f for smblctx "
			  "%llu, file %s timeout = %d\n",
			  (double)e->offset,
			  (double)e->count,
			  (unsigned long long)e->smblctx,
			  fsp_str_dbg(fsp),
			  (int)timeout));

		if (type & LOCKING_ANDX_CANCEL_LOCK) {
			struct blocking_lock_record *blr = NULL;

			if (num_locks > 1) {
				/*
				 * MS-CIFS (2.2.4.32.1) states that a cancel is honored if and only
				 * if the lock vector contains one entry. When given multiple cancel
				 * requests in a single PDU we expect the server to return an
				 * error. Windows servers seem to accept the request but only
				 * cancel the first lock.
				 * JRA - Do what Windows does (tm) :-).
				 */

#if 0
				/* MS-CIFS (2.2.4.32.1) behavior. */
				return NT_STATUS_DOS(ERRDOS,
						ERRcancelviolation);
#else
				/* Windows behavior. */
				if (i != 0) {
					DEBUG(10,("smbd_do_locking: ignoring subsequent "
						"cancel request\n"));
					continue;
				}
#endif
			}

			if (lp_blocking_locks(SNUM(conn))) {

				/* Schedule a message to ourselves to
				   remove the blocking lock record and
				   return the right error. */

				blr = blocking_lock_cancel_smb1(fsp,
						e->smblctx,
						e->offset,
						e->count,
						WINDOWS_LOCK,
						type,
						NT_STATUS_FILE_LOCK_CONFLICT);
				if (blr == NULL) {
					return NT_STATUS_DOS(
							ERRDOS,
							ERRcancelviolation);
				}
			}
			/* Remove a matching pending lock. */
			status = do_lock_cancel(fsp,
						e->smblctx,
						e->count,
						e->offset,
						WINDOWS_LOCK);
		} else {
			bool blocking_lock = timeout ? true : false;
			bool defer_lock = false;
			struct byte_range_lock *br_lck;
			uint64_t block_smblctx;

			br_lck = do_lock(req->sconn->msg_ctx,
					fsp,
					e->smblctx,
					e->count,
					e->offset, 
					e->brltype,
					WINDOWS_LOCK,
					blocking_lock,
					&status,
					&block_smblctx);

			if (br_lck && blocking_lock && ERROR_WAS_LOCK_DENIED(status)) {
				/* Windows internal resolution for blocking locks seems
				   to be about 200ms... Don't wait for less than that. JRA. */
				if (timeout != -1 && timeout < lp_lock_spin_time()) {
					timeout = lp_lock_spin_time();
				}
				defer_lock = true;
			}

			/* If a lock sent with timeout of zero would fail, and
			 * this lock has been requested multiple times,
			 * according to brl_lock_failed() we convert this
			 * request to a blocking lock with a timeout of between
			 * 150 - 300 milliseconds.
			 *
			 * If lp_lock_spin_time() has been set to 0, we skip
			 * this blocking retry and fail immediately.
			 *
			 * Replacement for do_lock_spin(). JRA. */

			if (!req->sconn->using_smb2 &&
			    br_lck && lp_blocking_locks(SNUM(conn)) &&
			    lp_lock_spin_time() && !blocking_lock &&
			    NT_STATUS_EQUAL((status),
				NT_STATUS_FILE_LOCK_CONFLICT))
			{
				defer_lock = true;
				timeout = lp_lock_spin_time();
			}

			if (br_lck && defer_lock) {
				/*
				 * A blocking lock was requested. Package up
				 * this smb into a queued request and push it
				 * onto the blocking lock queue.
				 */
				if(push_blocking_lock_request(br_lck,
							req,
							fsp,
							timeout,
							i,
							e->smblctx,
							e->brltype,
							WINDOWS_LOCK,
							e->offset,
							e->count,
							block_smblctx)) {
					TALLOC_FREE(br_lck);
					*async = true;
					return NT_STATUS_OK;
				}
			}

			TALLOC_FREE(br_lck);
		}

		if (!NT_STATUS_IS_OK(status)) {
			break;
		}
	}

	/* If any of the above locks failed, then we must unlock
	   all of the previous locks (X/Open spec). */

	if (num_locks != 0 && !NT_STATUS_IS_OK(status)) {

		if (type & LOCKING_ANDX_CANCEL_LOCK) {
			i = -1; /* we want to skip the for loop */
		}

		/*
		 * Ensure we don't do a remove on the lock that just failed,
		 * as under POSIX rules, if we have a lock already there, we
		 * will delete it (and we shouldn't) .....
		 */
		for(i--; i >= 0; i--) {
			struct smbd_lock_element *e = &locks[i];

			do_unlock(req->sconn->msg_ctx,
				fsp,
				e->smblctx,
				e->count,
				e->offset,
				WINDOWS_LOCK);
		}
		return status;
	}

	DEBUG(3, ("smbd_do_locking: %s type=%d num_locks=%d\n",
		  fsp_fnum_dbg(fsp), (unsigned int)type, num_locks));

	return NT_STATUS_OK;
}

NTSTATUS smbd_do_unlocking(struct smb_request *req,
			   files_struct *fsp,
			   uint16_t num_ulocks,
			   struct smbd_lock_element *ulocks)
{
	int i;

	for(i = 0; i < (int)num_ulocks; i++) {
		struct smbd_lock_element *e = &ulocks[i];
		NTSTATUS status;

		DEBUG(10,("%s: unlock start=%.0f, len=%.0f for "
			  "pid %u, file %s\n", __func__,
			  (double)e->offset,
			  (double)e->count,
			  (unsigned int)e->smblctx,
			  fsp_str_dbg(fsp)));

		if (e->brltype != UNLOCK_LOCK) {
			/* this can only happen with SMB2 */
			return NT_STATUS_INVALID_PARAMETER;
		}

		status = do_unlock(req->sconn->msg_ctx,
				fsp,
				e->smblctx,
				e->count,
				e->offset,
				WINDOWS_LOCK);

		DEBUG(10, ("%s: unlock returned %s\n", __func__,
			   nt_errstr(status)));

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	DEBUG(3, ("%s: %s num_ulocks=%d\n", __func__, fsp_fnum_dbg(fsp),
		  num_ulocks));

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a lockingX request.
****************************************************************************/

void reply_lockingX(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	unsigned char locktype;
	unsigned char oplocklevel;
	uint16_t num_ulocks;
	uint16_t num_locks;
	int32_t lock_timeout;
	int i;
	const uint8_t *data;
	bool large_file_format;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct smbd_lock_element *ulocks;
	struct smbd_lock_element *locks;
	bool async = false;

	START_PROFILE(SMBlockingX);

	if (req->wct < 8) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockingX);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+2, 0));
	locktype = CVAL(req->vwv+3, 0);
	oplocklevel = CVAL(req->vwv+3, 1);
	num_ulocks = SVAL(req->vwv+6, 0);
	num_locks = SVAL(req->vwv+7, 0);
	lock_timeout = IVAL(req->vwv+4, 0);
	large_file_format = ((locktype & LOCKING_ANDX_LARGE_FILES) != 0);

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlockingX);
		return;
	}

	data = req->buf;

	if (locktype & LOCKING_ANDX_CHANGE_LOCKTYPE) {
		/* we don't support these - and CANCEL_LOCK makes w2k
		   and XP reboot so I don't really want to be
		   compatible! (tridge) */
		reply_force_doserror(req, ERRDOS, ERRnoatomiclocks);
		END_PROFILE(SMBlockingX);
		return;
	}

	/* Check if this is an oplock break on a file
	   we have granted an oplock on.
	*/
	if (locktype & LOCKING_ANDX_OPLOCK_RELEASE) {
		/* Client can insist on breaking to none. */
		bool break_to_none = (oplocklevel == 0);
		bool result;

		DEBUG(5,("reply_lockingX: oplock break reply (%u) from client "
			 "for %s\n", (unsigned int)oplocklevel,
			 fsp_fnum_dbg(fsp)));

		/*
		 * Make sure we have granted an exclusive or batch oplock on
		 * this file.
		 */

		if (fsp->oplock_type == 0) {

			/* The Samba4 nbench simulator doesn't understand
			   the difference between break to level2 and break
			   to none from level2 - it sends oplock break
			   replies in both cases. Don't keep logging an error
			   message here - just ignore it. JRA. */

			DEBUG(5,("reply_lockingX: Error : oplock break from "
				 "client for %s (oplock=%d) and no "
				 "oplock granted on this file (%s).\n",
				 fsp_fnum_dbg(fsp), fsp->oplock_type,
				 fsp_str_dbg(fsp)));

			/* if this is a pure oplock break request then don't
			 * send a reply */
			if (num_locks == 0 && num_ulocks == 0) {
				END_PROFILE(SMBlockingX);
				return;
			} else {
				END_PROFILE(SMBlockingX);
				reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
				return;
			}
		}

		if ((fsp->sent_oplock_break == BREAK_TO_NONE_SENT) ||
		    (break_to_none)) {
			result = remove_oplock(fsp);
		} else {
			result = downgrade_oplock(fsp);
		}

		if (!result) {
			DEBUG(0, ("reply_lockingX: error in removing "
				  "oplock on file %s\n", fsp_str_dbg(fsp)));
			/* Hmmm. Is this panic justified? */
			smb_panic("internal tdb error");
		}

		/* if this is a pure oplock break request then don't send a
		 * reply */
		if (num_locks == 0 && num_ulocks == 0) {
			/* Sanity check - ensure a pure oplock break is not a
			   chained request. */
			if (CVAL(req->vwv+0, 0) != 0xff) {
				DEBUG(0,("reply_lockingX: Error : pure oplock "
					 "break is a chained %d request !\n",
					 (unsigned int)CVAL(req->vwv+0, 0)));
			}
			END_PROFILE(SMBlockingX);
			return;
		}
	}

	if (req->buflen <
	    (num_ulocks + num_locks) * (large_file_format ? 20 : 10)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockingX);
		return;
	}

	ulocks = talloc_array(req, struct smbd_lock_element, num_ulocks);
	if (ulocks == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlockingX);
		return;
	}

	locks = talloc_array(req, struct smbd_lock_element, num_locks);
	if (locks == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlockingX);
		return;
	}

	/* Data now points at the beginning of the list
	   of smb_unlkrng structs */
	for(i = 0; i < (int)num_ulocks; i++) {
		ulocks[i].smblctx = get_lock_pid(data, i, large_file_format);
		ulocks[i].count = get_lock_count(data, i, large_file_format);
		ulocks[i].offset = get_lock_offset(data, i, large_file_format);
		ulocks[i].brltype = UNLOCK_LOCK;
	}

	/* Now do any requested locks */
	data += ((large_file_format ? 20 : 10)*num_ulocks);

	/* Data now points at the beginning of the list
	   of smb_lkrng structs */

	for(i = 0; i < (int)num_locks; i++) {
		locks[i].smblctx = get_lock_pid(data, i, large_file_format);
		locks[i].count = get_lock_count(data, i, large_file_format);
		locks[i].offset = get_lock_offset(data, i, large_file_format);

		if (locktype & LOCKING_ANDX_SHARED_LOCK) {
			if (locktype & LOCKING_ANDX_CANCEL_LOCK) {
				locks[i].brltype = PENDING_READ_LOCK;
			} else {
				locks[i].brltype = READ_LOCK;
			}
		} else {
			if (locktype & LOCKING_ANDX_CANCEL_LOCK) {
				locks[i].brltype = PENDING_WRITE_LOCK;
			} else {
				locks[i].brltype = WRITE_LOCK;
			}
		}
	}

	status = smbd_do_unlocking(req, fsp, num_ulocks, ulocks);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBlockingX);
		reply_nterror(req, status);
		return;
	}

	status = smbd_do_locking(req, fsp,
				 locktype, lock_timeout,
				 num_locks, locks,
				 &async);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBlockingX);
		reply_nterror(req, status);
		return;
	}
	if (async) {
		END_PROFILE(SMBlockingX);
		return;
	}

	reply_outbuf(req, 2, 0);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	DEBUG(3, ("lockingX %s type=%d num_locks=%d num_ulocks=%d\n",
		  fsp_fnum_dbg(fsp), (unsigned int)locktype, num_locks, num_ulocks));

	END_PROFILE(SMBlockingX);
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a SMBreadbmpx (read block multiplex) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_readbmpx(struct smb_request *req)
{
	START_PROFILE(SMBreadBmpx);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBreadBmpx);
	return;
}

/****************************************************************************
 Reply to a SMBreadbs (read block multiplex secondary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_readbs(struct smb_request *req)
{
	START_PROFILE(SMBreadBs);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBreadBs);
	return;
}

/****************************************************************************
 Reply to a SMBsetattrE.
****************************************************************************/

void reply_setattrE(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_file_time ft;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsetattrE);
	ZERO_STRUCT(ft);

	if (req->wct < 7) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if(!fsp || (fsp->conn != conn)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		goto out;
	}

	/*
	 * Convert the DOS times into unix times.
	 */

	ft.atime = convert_time_t_to_timespec(
	    srv_make_unix_date2(req->vwv+3));
	ft.mtime = convert_time_t_to_timespec(
	    srv_make_unix_date2(req->vwv+5));
	ft.create_time = convert_time_t_to_timespec(
	    srv_make_unix_date2(req->vwv+1));

	reply_outbuf(req, 0, 0);

	/* 
	 * Patch from Ray Frush <frush@engr.colostate.edu>
	 * Sometimes times are sent as zero - ignore them.
	 */

	/* Ensure we have a valid stat struct for the source. */
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!(fsp->access_mask & FILE_WRITE_ATTRIBUTES)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	status = smb_set_file_time(conn, fsp, fsp->fsp_name, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	DEBUG( 3, ( "reply_setattrE %s actime=%u modtime=%u "
	       " createtime=%u\n",
		fsp_fnum_dbg(fsp),
		(unsigned int)ft.atime.tv_sec,
		(unsigned int)ft.mtime.tv_sec,
		(unsigned int)ft.create_time.tv_sec
		));
 out:
	END_PROFILE(SMBsetattrE);
	return;
}


/* Back from the dead for OS/2..... JRA. */

/****************************************************************************
 Reply to a SMBwritebmpx (write block multiplex primary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_writebmpx(struct smb_request *req)
{
	START_PROFILE(SMBwriteBmpx);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBwriteBmpx);
	return;
}

/****************************************************************************
 Reply to a SMBwritebs (write block multiplex secondary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_writebs(struct smb_request *req)
{
	START_PROFILE(SMBwriteBs);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBwriteBs);
	return;
}

/****************************************************************************
 Reply to a SMBgetattrE.
****************************************************************************/

void reply_getattrE(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int mode;
	files_struct *fsp;
	struct timespec create_ts;

	START_PROFILE(SMBgetattrE);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBgetattrE);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if(!fsp || (fsp->conn != conn)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		END_PROFILE(SMBgetattrE);
		return;
	}

	/* Do an fstat on this file */
	if(fsp_stat(fsp)) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		END_PROFILE(SMBgetattrE);
		return;
	}

	mode = dos_mode(conn, fsp->fsp_name);

	/*
	 * Convert the times into dos times. Set create
	 * date to be last modify date as UNIX doesn't save
	 * this.
	 */

	reply_outbuf(req, 11, 0);

	create_ts = get_create_timespec(conn, fsp, fsp->fsp_name);
	srv_put_dos_date2((char *)req->outbuf, smb_vwv0, create_ts.tv_sec);
	srv_put_dos_date2((char *)req->outbuf, smb_vwv2,
			  convert_timespec_to_time_t(fsp->fsp_name->st.st_ex_atime));
	/* Should we check pending modtime here ? JRA */
	srv_put_dos_date2((char *)req->outbuf, smb_vwv4,
			  convert_timespec_to_time_t(fsp->fsp_name->st.st_ex_mtime));

	if (mode & FILE_ATTRIBUTE_DIRECTORY) {
		SIVAL(req->outbuf, smb_vwv6, 0);
		SIVAL(req->outbuf, smb_vwv8, 0);
	} else {
		uint32_t allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn,fsp, &fsp->fsp_name->st);
		SIVAL(req->outbuf, smb_vwv6, (uint32_t)fsp->fsp_name->st.st_ex_size);
		SIVAL(req->outbuf, smb_vwv8, allocation_size);
	}
	SSVAL(req->outbuf,smb_vwv10, mode);

	DEBUG( 3, ( "reply_getattrE %s\n", fsp_fnum_dbg(fsp)));

	END_PROFILE(SMBgetattrE);
	return;
}
