/*
   Samba-VirusFilter VFS modules
   Copyright (C) 2010-2011 SATOH Fumiyasu @ OSS Technology, Inc.

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

#ifndef _SVF_COMMON_H
#define _SVF_COMMON_H

/* Samba common include file */
#include "includes.h"

#if SAMBA_VERSION_NUMBER >= 30600
#  include "smbd/smbd.h"
#  include "smbd/globals.h"
#  include "system/filesys.h"
#  include "transfer_file.h"
#  include "auth.h"
#  include "passdb.h"
#  include "../librpc/gen_ndr/ndr_netlogon.h"
#endif

#if (SMB_VFS_INTERFACE_VERSION < 27)
#error "Samba 3.5+ required (SMB_VFS_INTERFACE_VERSION >= 27)"
#endif

/* Undefine Samba's PACKAGE_* macros */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

/* Samba debug classs for SVF */
#undef DBGC_CLASS
#define DBGC_CLASS svf_debug_level
extern int svf_debug_level;

/* Samba's global variable */
extern userdom_struct current_user_info;

#include "svf-config.h"

#define SVF_VERSION PACKAGE_VERSION

/* ====================================================================== */

typedef enum {
	SVF_ACTION_DO_NOTHING,
	SVF_ACTION_QUARANTINE,
	SVF_ACTION_DELETE,
	/* FIXME: SVF_ACTION_RENAME, */
} svf_action;

typedef enum {
	SVF_RESULT_OK,
	SVF_RESULT_CLEAN,
	SVF_RESULT_ERROR,
	SVF_RESULT_INFECTED,
	/* FIXME: SVF_RESULT_SUSPECTED, */
	/* FIXME: SVF_RESULT_RISKWARE, */
} svf_result;

#if SAMBA_VERSION_NUMBER >= 30600
#  define conn_session_info(conn)	((conn)->session_info)
#  define conn_socket(conn)		((conn)->sconn->sock)
#  define conn_domain_name(conn)	((conn)->session_info->info3->base.domain.string)
#  define conn_client_name(conn)	((conn)->sconn->client_id.name)
#  define conn_client_addr(conn, addr)	((conn)->sconn->client_id.addr)
#else
#  define conn_session_info(conn)	((conn)->server_info)
#  define conn_socket(conn)		(get_client_fd())
#  define conn_domain_name(conn)	pdb_get_domain(((conn)->server_info->sam_account))
#  define conn_client_name(conn)	(client_name(get_client_fd()))
#  define conn_client_addr(conn, addr)	(client_addr(get_client_fd(), (addr), sizeof(addr)))
#endif

#define conn_server_addr(conn, addr)	client_socket_addr(conn_socket(conn), (addr), sizeof(addr));

#endif /* _SVF_COMMON_H */

