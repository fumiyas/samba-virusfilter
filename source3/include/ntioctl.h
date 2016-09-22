/* 
   Unix SMB/CIFS implementation.
   NT ioctl code constants
   Copyright (C) Andrew Tridgell              2002

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

#ifndef _NTIOCTL_H
#define _NTIOCTL_H

#define IO_REPARSE_TAG_SYMLINK	     0xA000000C
#define SYMLINK_FLAG_RELATIVE	     0x00000001

#define IO_REPARSE_TAG_MOUNT_POINT   0xA0000003
#define IO_REPARSE_TAG_HSM           0xC0000004
#define IO_REPARSE_TAG_SIS           0x80000007
#define IO_REPARSE_TAG_DFS	     0x8000000A


/* For FSCTL_GET_SHADOW_COPY_DATA ...*/
typedef char SHADOW_COPY_LABEL[25];

struct shadow_copy_data {
	/* Total number of shadow volumes currently mounted */
	uint32_t num_volumes;
	/* Concatenated list of labels */
	SHADOW_COPY_LABEL *labels;
};


#endif /* _NTIOCTL_H */
