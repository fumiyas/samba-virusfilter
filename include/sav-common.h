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

#ifndef _SAV_COMMON_H
#define _SAV_COMMON_H

/* Samba common include file */
#include "includes.h"

#if (SMB_VFS_INTERFACE_VERSION < 22)
#error "Samba 3.2 required (SMB_VFS_INTERFACE_VERSION >= 22)"
#endif

/* Undefine Samba's PACKAGE_* macros */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

/* Samba debug classs for SAV */
#undef DBGC_CLASS
#define DBGC_CLASS sav_debug_level
extern int sav_debug_level;

/* Samba's global variable */
extern userdom_struct current_user_info;

#include "sav-config.h"

/* ====================================================================== */

typedef enum {
	SAV_ACTION_DO_NOTHING,
	SAV_ACTION_QUARANTINE,
	SAV_ACTION_DELETE,
	/* FIXME: SAV_ACTION_RENAME, */
} sav_action;

typedef enum {
	SAV_RESULT_OK,
	SAV_RESULT_CLEAN,
	SAV_RESULT_ERROR,
	SAV_RESULT_INFECTED,
	/* FIXME: SAV_RESULT_SUSPECTED, */
	/* FIXME: SAV_RESULT_RISKWARE, */
} sav_result;

#endif /* _SAV_COMMON_H */

