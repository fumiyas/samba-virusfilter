/*
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WINBIND_NSS_CONFIG_H
#define _WINBIND_NSS_CONFIG_H

/* shutup the compiler warnings due to krb5.h on 64-bit sles9 */
#ifdef SIZEOF_LONG
#undef SIZEOF_LONG
#endif

/* Include header files from data in config.h file */

#ifndef NO_CONFIG_H
#include "../replace/replace.h"
#endif

#include "system/filesys.h"
#include "system/network.h"
#include "system/passwd.h"

#include "nsswitch/winbind_nss.h"

/* I'm trying really hard not to include anything from smb.h with the
   result of some silly looking redeclaration of structures. */

#ifndef FSTRING_LEN
#define FSTRING_LEN 256
typedef char fstring[FSTRING_LEN];
#ifndef fstrcpy
#define fstrcpy(d,s) \
do { \
        const char *_fstrcpy_src = (const char *)(s); \
        strlcpy((d),_fstrcpy_src ? _fstrcpy_src : "",sizeof(fstring)); \
} while (0)
#endif
#endif

/* Some systems (SCO) treat UNIX domain sockets as FIFOs */

#ifndef S_IFSOCK
#define S_IFSOCK S_IFIFO
#endif

#ifndef S_ISSOCK
#define S_ISSOCK(mode)  ((mode & S_IFSOCK) == S_IFSOCK)
#endif

#endif
