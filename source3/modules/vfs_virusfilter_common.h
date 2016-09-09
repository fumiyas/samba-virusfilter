/*
   Samba-VirusFilter VFS modules
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

#ifndef _VIRUSFILTER_COMMON_H
#define _VIRUSFILTER_COMMON_H

#include <stdint.h>
#include <time.h>
/* Samba common include file */
#include "includes.h"

#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "system/filesys.h"
#include "transfer_file.h"
#include "auth.h"
#include "passdb.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../lib/tsocket/tsocket.h"

#if (SMB_VFS_INTERFACE_VERSION < 28)
#error "Samba 3.6+ required (SMB_VFS_INTERFACE_VERSION >= 28)"
#endif

/* Undefine Samba's PACKAGE_* macros */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

/* Samba debug classs for VIRUSFILTER */
#undef DBGC_CLASS
#define DBGC_CLASS virusfilter_debug_level
extern int virusfilter_debug_level;

/* Samba's global variable */
extern userdom_struct current_user_info;

#include "vfs_virusfilter_config.h"

#define VIRUSFILTER_VERSION PACKAGE_VERSION

/* ====================================================================== */

typedef enum {
	VIRUSFILTER_ACTION_DO_NOTHING,
	VIRUSFILTER_ACTION_QUARANTINE,
	VIRUSFILTER_ACTION_RENAME,
	VIRUSFILTER_ACTION_DELETE,
} virusfilter_action;

typedef enum {
	VIRUSFILTER_RESULT_OK,
	VIRUSFILTER_RESULT_CLEAN,
	VIRUSFILTER_RESULT_ERROR,
	VIRUSFILTER_RESULT_INFECTED,
	/* FIXME: VIRUSFILTER_RESULT_SUSPECTED, */
	/* FIXME: VIRUSFILTER_RESULT_RISKWARE, */
} virusfilter_result;

#define conn_session_info(conn)		((conn)->session_info)
#if SAMBA_VERSION_NUMBER >= 40200
# define conn_socket(conn)		((conn)->transport.sock)
#else
# define conn_socket(conn)		((conn)->sconn->sock)
#endif
#define conn_domain_name(conn)		((conn)->session_info->info->domain_name)
#define conn_client_name(conn)		((conn)->sconn->remote_hostname)
#define conn_client_addr(conn)		tsocket_address_inet_addr_string((conn)->sconn->remote_address, talloc_tos())

#define conn_server_addr(conn)	tsocket_address_inet_addr_string((conn)->sconn->local_address, talloc_tos())

#endif /* _VIRUSFILTER_COMMON_H */

