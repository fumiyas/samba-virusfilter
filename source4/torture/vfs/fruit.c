/*
   Unix SMB/CIFS implementation.

   vfs_fruit tests

   Copyright (C) Ralph Boehme 2014

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

#include "includes.h"
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smb2_create_ctx.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "MacExtensions.h"
#include "lib/util/tsort.h"

#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/vfs/proto.h"
#include "librpc/gen_ndr/ndr_ioctl.h"

#define BASEDIR "vfs_fruit_dir"
#define FNAME_CC_SRC "testfsctl.dat"
#define FNAME_CC_DST "testfsctl2.dat"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
		    "(%s) Incorrect status %s - should be %s\n", \
		    __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			       "(%s) Incorrect value %s=%u - should be %u\n", \
			       __location__, #v, (unsigned)v, (unsigned)correct); \
		ret = false; \
		goto done; \
	}} while (0)

static bool check_stream_list(struct smb2_tree *tree,
			      struct torture_context *tctx,
			      const char *fname,
			      int num_exp,
			      const char **exp,
			      bool is_dir);

static int qsort_string(char * const *s1, char * const *s2)
{
	return strcmp(*s1, *s2);
}

static int qsort_stream(const struct stream_struct * s1, const struct stream_struct *s2)
{
	return strcmp(s1->stream_name.s, s2->stream_name.s);
}

/*
 * REVIEW:
 * This is hokey, but what else can we do?
 */
#if defined(HAVE_ATTROPEN) || defined(FREEBSD)
#define AFPINFO_EA_NETATALK "org.netatalk.Metadata"
#define AFPRESOURCE_EA_NETATALK "org.netatalk.ResourceFork"
#else
#define AFPINFO_EA_NETATALK "user.org.netatalk.Metadata"
#define AFPRESOURCE_EA_NETATALK "user.org.netatalk.ResourceFork"
#endif

/*
The metadata xattr char buf below contains the following attributes:

-------------------------------------------------------------------------------
Entry ID   : 00000008 : File Dates Info
Offset     : 00000162 : 354
Length     : 00000010 : 16

-DATE------:          : (GMT)                    : (Local)
create     : 1B442169 : Mon Jun 30 13:23:53 2014 : Mon Jun 30 15:23:53 2014
modify     : 1B442169 : Mon Jun 30 13:23:53 2014 : Mon Jun 30 15:23:53 2014
backup     : 80000000 : Unknown or Initial
access     : 1B442169 : Mon Jun 30 13:23:53 2014 : Mon Jun 30 15:23:53 2014

-RAW DUMP--:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F : (ASCII)
00000000   : 1B 44 21 69 1B 44 21 69 80 00 00 00 1B 44 21 69 : .D!i.D!i.....D!i

-------------------------------------------------------------------------------
Entry ID   : 00000009 : Finder Info
Offset     : 0000007A : 122
Length     : 00000020 : 32

-FInfo-----:
Type       : 42415252 : BARR
Creator    : 464F4F4F : FOOO
isAlias    : 0
Invisible  : 1
hasBundle  : 0
nameLocked : 0
Stationery : 0
CustomIcon : 0
Reserved   : 0
Inited     : 0
NoINITS    : 0
Shared     : 0
SwitchLaunc: 0
Hidden Ext : 0
color      : 000      : none
isOnDesk   : 0
Location v : 0000     : 0
Location h : 0000     : 0
Fldr       : 0000     : ..

-FXInfo----:
Rsvd|IconID: 0000     : 0
Rsvd       : 0000     : ..
Rsvd       : 0000     : ..
Rsvd       : 0000     : ..
AreInvalid : 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
CustomBadge: 0
ObjctIsBusy: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
RoutingInfo: 0
unknown bit: 0
unknown bit: 0
Rsvd|commnt: 0000     : 0
PutAway    : 00000000 : 0

-RAW DUMP--:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F : (ASCII)
00000000   : 42 41 52 52 46 4F 4F 4F 40 00 00 00 00 00 00 00 : BARRFOOO@.......
00000010   : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 : ................

-------------------------------------------------------------------------------
Entry ID   : 0000000E : AFP File Info
Offset     : 00000172 : 370
Length     : 00000004 : 4

-RAW DUMP--:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F : (ASCII)
00000000   : 00 00 01 A1                                     : ....
 */

char metadata_xattr[] = {
	0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
	0x00, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x01, 0x62, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
	0x00, 0x7a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
	0x00, 0x0e, 0x00, 0x00, 0x01, 0x72, 0x00, 0x00,
	0x00, 0x04, 0x80, 0x44, 0x45, 0x56, 0x00, 0x00,
	0x01, 0x76, 0x00, 0x00, 0x00, 0x08, 0x80, 0x49,
	0x4e, 0x4f, 0x00, 0x00, 0x01, 0x7e, 0x00, 0x00,
	0x00, 0x08, 0x80, 0x53, 0x59, 0x4e, 0x00, 0x00,
	0x01, 0x86, 0x00, 0x00, 0x00, 0x08, 0x80, 0x53,
	0x56, 0x7e, 0x00, 0x00, 0x01, 0x8e, 0x00, 0x00,
	0x00, 0x04, 0x42, 0x41, 0x52, 0x52, 0x46, 0x4f,
	0x4f, 0x4f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1b, 0x44, 0x21, 0x69, 0x1b, 0x44,
	0x21, 0x69, 0x80, 0x00, 0x00, 0x00, 0x1b, 0x44,
	0x21, 0x69, 0x00, 0x00, 0x01, 0xa1, 0x00, 0xfd,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc1, 0x20,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0xe3,
	0x86, 0x53, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x01,
	0x00, 0x00
};

/*
The buf below contains the following AppleDouble encoded data:

-------------------------------------------------------------------------------
MagicNumber: 00051607                                        : AppleDouble
Version    : 00020000                                        : Version 2
Filler     : 4D 61 63 20 4F 53 20 58 20 20 20 20 20 20 20 20 : Mac OS X
Num. of ent: 0002                                            : 2

-------------------------------------------------------------------------------
Entry ID   : 00000009 : Finder Info
Offset     : 00000032 : 50
Length     : 00000EB0 : 3760

-FInfo-----:
Type       : 54455854 : TEXT
Creator    : 21526368 : !Rch
...

-EA--------:
pad        : 0000     : ..
magic      : 41545452 : ATTR
debug_tag  : 0007F98E : 522638
total_size : 00000EE2 : 3810
data_start : 00000078 : 120
data_length: 00000000 : 0
reserved[0]: 00000000 : ....
reserved[1]: 00000000 : ....
reserved[2]: 00000000 : ....
flags      : 0000     : ..
num_attrs  : 0000     : 0

-------------------------------------------------------------------------------
Entry ID   : 00000002 : Resource Fork
Offset     : 00000EE2 : 3810
Length     : 0000011E : 286

-RAW DUMP--:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F : (ASCII)
00000000   : 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 1E : ................
00000010   : 54 68 69 73 20 72 65 73 6F 75 72 63 65 20 66 6F : This resource fo
00000020   : 72 6B 20 69 6E 74 65 6E 74 69 6F 6E 61 6C 6C 79 : rk intentionally
00000030   : 20 6C 65 66 74 20 62 6C 61 6E 6B 20 20 20 00 00 :  left blank   ..
...
00000110   : 00 00 00 00 00 00 00 00 00 1C 00 1E FF FF       : ..............
*/
static char osx_adouble_w_xattr[] = {
	0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00,
	0x4d, 0x61, 0x63, 0x20, 0x4f, 0x53, 0x20, 0x58,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
	0x00, 0x32, 0x00, 0x00, 0x0e, 0xb0, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x00, 0x0e, 0xe2, 0x00, 0x00,
	0x01, 0x1e, 0x54, 0x45, 0x58, 0x54, 0x21, 0x52,
	0x63, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x41, 0x54, 0x54, 0x52,
	0x00, 0x07, 0xf9, 0x8e, 0x00, 0x00, 0x0e, 0xe2,
	0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x1e, 0x54, 0x68, 0x69, 0x73, 0x20, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20,
	0x66, 0x6f, 0x72, 0x6b, 0x20, 0x69, 0x6e, 0x74,
	0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c,
	0x6c, 0x79, 0x20, 0x6c, 0x65, 0x66, 0x74, 0x20,
	0x62, 0x6c, 0x61, 0x6e, 0x6b, 0x20, 0x20, 0x20,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x1c, 0x00, 0x1e, 0xff, 0xff
};

/**
 * talloc and intialize an AfpInfo
 **/
static AfpInfo *torture_afpinfo_new(TALLOC_CTX *mem_ctx)
{
	AfpInfo *info;

	info = talloc_zero(mem_ctx, AfpInfo);
	if (info == NULL) {
		return NULL;
	}

	info->afpi_Signature = AFP_Signature;
	info->afpi_Version = AFP_Version;
	info->afpi_BackupTime = AFP_BackupTime;

	return info;
}

/**
 * Pack AfpInfo into a talloced buffer
 **/
static char *torture_afpinfo_pack(TALLOC_CTX *mem_ctx,
				  AfpInfo *info)
{
	char *buf;

	buf = talloc_array(mem_ctx, char, AFP_INFO_SIZE);
	if (buf == NULL) {
		return NULL;
	}

	RSIVAL(buf, 0, info->afpi_Signature);
	RSIVAL(buf, 4, info->afpi_Version);
	RSIVAL(buf, 12, info->afpi_BackupTime);
	memcpy(buf + 16, info->afpi_FinderInfo, sizeof(info->afpi_FinderInfo));

	return buf;
}

/**
 * Unpack AfpInfo
 **/
#if 0
static void torture_afpinfo_unpack(AfpInfo *info, char *data)
{
	info->afpi_Signature = RIVAL(data, 0);
	info->afpi_Version = RIVAL(data, 4);
	info->afpi_BackupTime = RIVAL(data, 12);
	memcpy(info->afpi_FinderInfo, (const char *)data + 16,
	       sizeof(info->afpi_FinderInfo));
}
#endif

static bool torture_write_afpinfo(struct smb2_tree *tree,
				  struct torture_context *tctx,
				  TALLOC_CTX *mem_ctx,
				  const char *fname,
				  AfpInfo *info)
{
	struct smb2_handle handle;
	struct smb2_create io;
	NTSTATUS status;
	const char *full_name;
	char *infobuf;
	bool ret = true;

	full_name = talloc_asprintf(mem_ctx, "%s%s", fname, AFPINFO_STREAM_NAME);
	if (full_name == NULL) {
	    torture_comment(tctx, "talloc_asprintf error\n");
	    return false;
	}
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.create_options = 0;
	io.in.fname = full_name;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	handle = io.out.file.handle;

	infobuf = torture_afpinfo_pack(mem_ctx, info);
	if (infobuf == NULL) {
		return false;
	}

	status = smb2_util_write(tree, handle, infobuf, 0, AFP_INFO_SIZE);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, handle);

done:
	return ret;
}

/**
 * Read 'count' bytes at 'offset' from stream 'fname:sname' and
 * compare against buffer 'value'
 **/
static bool check_stream(struct smb2_tree *tree,
			 const char *location,
			 struct torture_context *tctx,
			 TALLOC_CTX *mem_ctx,
			 const char *fname,
			 const char *sname,
			 off_t read_offset,
			 size_t read_count,
			 off_t comp_offset,
			 size_t comp_count,
			 const char *value)
{
	struct smb2_handle handle;
	struct smb2_create create;
	struct smb2_read r;
	NTSTATUS status;
	char *full_name;
	bool ret = true;

	full_name = talloc_asprintf(mem_ctx, "%s%s", fname, sname);
	if (full_name == NULL) {
	    torture_comment(tctx, "talloc_asprintf error\n");
	    return false;
	}
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_FILE_READ_DATA;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.fname = full_name;

	torture_comment(tctx, "Open stream %s\n", full_name);

	status = smb2_create(tree, mem_ctx, &create);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(full_name);
		if (value == NULL) {
			return true;
		}
		torture_comment(tctx, "Unable to open stream %s\n", full_name);
		return false;
	}

	handle = create.out.file.handle;
	if (value == NULL) {
		TALLOC_FREE(full_name);
		smb2_util_close(tree, handle);
		return true;
	}

	ZERO_STRUCT(r);
	r.in.file.handle = handle;
	r.in.length      = read_count;
	r.in.offset      = read_offset;

	status = smb2_read(tree, tree, &r);

	torture_assert_ntstatus_ok_goto(
		tctx, status, ret, done,
		talloc_asprintf(tctx, "(%s) Failed to read %lu bytes from stream '%s'\n",
				location, (long)strlen(value), full_name));

	torture_assert_goto(tctx, r.out.data.length == read_count, ret, done,
			    talloc_asprintf(tctx, "smb2_read returned %jd bytes, expected %jd\n",
					    (intmax_t)r.out.data.length, (intmax_t)read_count));

	torture_assert_goto(
		tctx, memcmp(r.out.data.data + comp_offset, value, comp_count) == 0,
		ret, done,
		talloc_asprintf(tctx, "(%s) Bad data in stream\n", location));

done:
	TALLOC_FREE(full_name);
	smb2_util_close(tree, handle);
	return ret;
}

/**
 * Read 'count' bytes at 'offset' from stream 'fname:sname' and
 * compare against buffer 'value'
 **/
static ssize_t read_stream(struct smb2_tree *tree,
			   const char *location,
			   struct torture_context *tctx,
			   TALLOC_CTX *mem_ctx,
			   const char *fname,
			   const char *sname,
			   off_t read_offset,
			   size_t read_count)
{
	struct smb2_handle handle;
	struct smb2_create create;
	struct smb2_read r;
	NTSTATUS status;
	const char *full_name;
	bool ret = true;

	full_name = talloc_asprintf(mem_ctx, "%s%s", fname, sname);
	if (full_name == NULL) {
	    torture_comment(tctx, "talloc_asprintf error\n");
	    return -1;
	}
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_FILE_READ_DATA;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.fname = full_name;

	torture_comment(tctx, "Open stream %s\n", full_name);

	status = smb2_create(tree, mem_ctx, &create);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Unable to open stream %s\n",
				full_name);
		return -1;
	}

	handle = create.out.file.handle;

	ZERO_STRUCT(r);
	r.in.file.handle = handle;
	r.in.length      = read_count;
	r.in.offset      = read_offset;

	status = smb2_read(tree, tree, &r);
	if (!NT_STATUS_IS_OK(status)) {
		CHECK_STATUS(status, NT_STATUS_END_OF_FILE);
	}

	smb2_util_close(tree, handle);

done:
	if (ret == false) {
		return -1;
	}
	return r.out.data.length;
}

/**
 * Read 'count' bytes at 'offset' from stream 'fname:sname' and
 * compare against buffer 'value'
 **/
static bool write_stream(struct smb2_tree *tree,
			 const char *location,
			 struct torture_context *tctx,
			 TALLOC_CTX *mem_ctx,
			 const char *fname,
			 const char *sname,
			 off_t offset,
			 size_t size,
			 const char *value)
{
	struct smb2_handle handle;
	struct smb2_create create;
	NTSTATUS status;
	const char *full_name;

	full_name = talloc_asprintf(mem_ctx, "%s%s", fname, sname);
	if (full_name == NULL) {
	    torture_comment(tctx, "talloc_asprintf error\n");
	    return false;
	}
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_FILE_WRITE_DATA;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.fname = full_name;

	status = smb2_create(tree, mem_ctx, &create);
	if (!NT_STATUS_IS_OK(status)) {
		if (value == NULL) {
			return true;
		} else {
			torture_comment(tctx, "Unable to open stream %s\n",
			    full_name);
			sleep(10000000);
			return false;
		}
	}

	handle = create.out.file.handle;
	if (value == NULL) {
		return true;
	}

	status = smb2_util_write(tree, handle, value, offset, size);

	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "(%s) Failed to write %lu bytes to "
		    "stream '%s'\n", location, (long)size, full_name);
		return false;
	}

	smb2_util_close(tree, handle);
	return true;
}

static bool torture_setup_local_xattr(struct torture_context *tctx,
				      const char *path_option,
				      const char *name,
				      const char *xattr,
				      const char *metadata,
				      size_t size)
{
	int ret = true;
	int result;
	const char *spath;
	char *path;

	spath = torture_setting_string(tctx, path_option, NULL);
	if (spath == NULL) {
		printf("No sharepath for option %s\n", path_option);
		return false;
	}

	path = talloc_asprintf(tctx, "%s/%s", spath, name);

	result = setxattr(path, xattr, metadata, size, 0);
	if (result != 0) {
		ret = false;
	}

	TALLOC_FREE(path);

	return ret;
}

static bool torture_setup_local_file(struct torture_context *tctx,
				     const char *path_option,
				     const char *name,
				     const char *buf,
				     size_t size)
{
	int fd;
	const char *spath;
	char *path;
	ssize_t rsize;

	spath = torture_setting_string(tctx, path_option, NULL);
	if (spath == NULL) {
		printf("No sharepath for option %s\n", path_option);
		return false;
	}

	path = talloc_asprintf(tctx, "%s/%s", spath, name);
	if (path == NULL) {
		return false;
	}

	fd = creat(path, S_IRWXU);
	TALLOC_FREE(path);
	if (fd == -1) {
		return false;
	}

	if ((buf == NULL) || (size == 0)) {
		close(fd);
		return true;
	}

	rsize = write(fd, buf, size);
	if (rsize != size) {
		return false;
	}

	close(fd);

	return true;
}

/**
 * Create a file or directory
 **/
static bool torture_setup_file(TALLOC_CTX *mem_ctx, struct smb2_tree *tree,
			       const char *name, bool dir)
{
	struct smb2_create io;
	NTSTATUS status;

	smb2_util_unlink(tree, name);
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = name;
	if (dir) {
		io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		io.in.share_access &= ~NTCREATEX_SHARE_ACCESS_DELETE;
		io.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
		io.in.create_disposition = NTCREATEX_DISP_CREATE;
	}

	status = smb2_create(tree, mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = smb2_util_close(tree, io.out.file.handle);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return true;
}

static bool enable_aapl(struct torture_context *tctx,
			struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	bool ret = true;
	struct smb2_create io;
	DATA_BLOB data;
	struct smb2_create_blob *aapl = NULL;
	uint32_t aapl_server_caps;
	uint32_t expexted_scaps = (SMB2_CRTCTX_AAPL_UNIX_BASED |
				   SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
				   SMB2_CRTCTX_AAPL_SUPPORTS_NFS_ACE |
				   SMB2_CRTCTX_AAPL_SUPPORTS_OSX_COPYFILE);
	bool is_osx_server = torture_setting_bool(tctx, "osx", false);

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access = (NTCREATEX_SHARE_ACCESS_DELETE |
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE);
	io.in.fname = "";

	/*
	 * Issuing an SMB2/CREATE with a suitably formed AAPL context,
	 * controls behaviour of Apple's SMB2 extensions for the whole
	 * session!
	 */

	data = data_blob_talloc(mem_ctx, NULL, 3 * sizeof(uint64_t));
	SBVAL(data.data, 0, SMB2_CRTCTX_AAPL_SERVER_QUERY);
	SBVAL(data.data, 8, (SMB2_CRTCTX_AAPL_SERVER_CAPS |
			     SMB2_CRTCTX_AAPL_VOLUME_CAPS |
			     SMB2_CRTCTX_AAPL_MODEL_INFO));
	SBVAL(data.data, 16, (SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
			      SMB2_CRTCTX_AAPL_UNIX_BASED |
			      SMB2_CRTCTX_AAPL_SUPPORTS_NFS_ACE));

	status = smb2_create_blob_add(tctx, &io.in.blobs, "AAPL", data);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create_blob_add");

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create");

	status = smb2_util_close(tree, io.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_util_close");

	/*
	 * Now check returned AAPL context
	 */
	torture_comment(tctx, "Comparing returned AAPL capabilities\n");

	aapl = smb2_create_blob_find(&io.out.blobs,
				     SMB2_CREATE_TAG_AAPL);
	torture_assert_goto(tctx, aapl != NULL, ret, done, "missing AAPL context");

	if (!is_osx_server) {
		torture_assert_goto(tctx, aapl->data.length == 50, ret, done, "bad AAPL size");
	}

	aapl_server_caps = BVAL(aapl->data.data, 16);
	torture_assert_goto(tctx, aapl_server_caps == expexted_scaps,
			    ret, done, "bad AAPL caps");

done:
	talloc_free(mem_ctx);
	return ret;
}

static bool test_read_netatalk_metadata(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_read_metadata";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	ssize_t len;
	const char *localdir = NULL;

	torture_comment(tctx, "Checking metadata access\n");

	localdir = torture_setting_string(tctx, "localdir", NULL);
	if (localdir == NULL) {
		torture_skip(tctx, "Need localdir for test");
	}

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, testdirh);

	ret = torture_setup_file(mem_ctx, tree, fname, false);
	if (ret == false) {
		goto done;
	}

	ret = torture_setup_local_xattr(tctx, "localdir",
					BASEDIR "/torture_read_metadata",
					AFPINFO_EA_NETATALK,
					metadata_xattr, sizeof(metadata_xattr));
	if (ret == false) {
		goto done;
	}

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   0, 60, 0, 4, "AFP");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   0, 60, 16, 8, "BARRFOOO");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   16, 8, 0, 3, "AFP");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	/* Check reading offset and read size > sizeof(AFPINFO_STREAM) */

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 0, 61);
	CHECK_VALUE(len, 60);

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 59, 2);
	CHECK_VALUE(len, 2);

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 60, 1);
	CHECK_VALUE(len, 1);

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 61, 1);
	CHECK_VALUE(len, 0);

done:
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_read_afpinfo(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_read_metadata";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	ssize_t len;
	AfpInfo *info;
	const char *type_creator = "SMB,OLE!";

	torture_comment(tctx, "Checking metadata access\n");

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir failed");
	smb2_util_close(tree, testdirh);

	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file failed");

	info = torture_afpinfo_new(mem_ctx);
	torture_assert_goto(tctx, info != NULL, ret, done, "torture_afpinfo_new failed");

	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_write_afpinfo failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   0, 60, 0, 4, "AFP");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   0, 60, 16, 8, type_creator);
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	/*
	 * OS X ignores offset <= 60 and treats the as
	 * offset=0. Reading from offsets > 60 returns EOF=0.
	 */

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   16, 8, 0, 8, "AFP\0\0\0\001\0");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 0, 61);
	torture_assert_goto(tctx, len == 60, ret, done, "read_stream failed");

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 59, 2);
	torture_assert_goto(tctx, len == 2, ret, done, "read_stream failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   59, 2, 0, 2, "AF");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 60, 1);
	torture_assert_goto(tctx, len == 1, ret, done, "read_stream failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   60, 1, 0, 1, "A");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream failed");

	len = read_stream(tree, __location__, tctx, mem_ctx, fname,
			  AFPINFO_STREAM, 61, 1);
	torture_assert_goto(tctx, len == 0, ret, done, "read_stream failed");

done:
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_write_atalk_metadata(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_write_metadata";
	const char *type_creator = "SMB,OLE!";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	AfpInfo *info;

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, testdirh);

	ret = torture_setup_file(mem_ctx, tree, fname, false);
	if (ret == false) {
		goto done;
	}

	info = torture_afpinfo_new(mem_ctx);
	if (info == NULL) {
		goto done;
	}

	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	ret &= check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			    0, 60, 16, 8, type_creator);

done:
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_write_atalk_rfork_io(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_write_rfork_io";
	const char *rfork = BASEDIR "\\torture_write_rfork_io" AFPRESOURCE_STREAM_NAME;
	const char *rfork_content = "1234567890";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;

	union smb_open io;
	struct smb2_handle filehandle;
	union smb_fileinfo finfo;
	union smb_setfileinfo sinfo;

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, testdirh);

	ret = torture_setup_file(mem_ctx, tree, fname, false);
	if (ret == false) {
		goto done;
	}

	torture_comment(tctx, "(%s) writing to resource fork\n",
	    __location__);

	ret &= write_stream(tree, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM_NAME,
			    10, 10, rfork_content);

	ret &= check_stream(tree, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM_NAME,
			    0, 20, 10, 10, rfork_content);

	/* Check size after write */

	ZERO_STRUCT(io);
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
		SEC_FILE_WRITE_ATTRIBUTE;
	io.smb2.in.fname = rfork;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	filehandle = io.smb2.out.file.handle;

	torture_comment(tctx, "(%s) check resource fork size after write\n",
	    __location__);

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_ALL_INFORMATION;
	finfo.generic.in.file.handle = filehandle;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (finfo.all_info.out.size != 20) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) Incorrect resource fork size\n",
			       __location__);
		ret = false;
		smb2_util_close(tree, filehandle);
		goto done;
	}
	smb2_util_close(tree, filehandle);

	/* Write at large offset */

	torture_comment(tctx, "(%s) writing to resource fork at large offset\n",
			__location__);

	ret &= write_stream(tree, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM_NAME,
			    (off_t)1<<32, 10, rfork_content);

	ret &= check_stream(tree, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM_NAME,
			    (off_t)1<<32, 10, 0, 10, rfork_content);

	/* Truncate back to size of 1 byte */

	torture_comment(tctx, "(%s) truncate resource fork and check size\n",
			__location__);

	ZERO_STRUCT(io);
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.desired_access = SEC_FILE_ALL;
	io.smb2.in.fname = rfork;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	filehandle = io.smb2.out.file.handle;

	ZERO_STRUCT(sinfo);
	sinfo.end_of_file_info.level =
		RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sinfo.end_of_file_info.in.file.handle = filehandle;
	sinfo.end_of_file_info.in.size = 1;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, filehandle);

	/* Now check size */
	ZERO_STRUCT(io);
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
		SEC_FILE_WRITE_ATTRIBUTE;
	io.smb2.in.fname = rfork;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	filehandle = io.smb2.out.file.handle;

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_ALL_INFORMATION;
	finfo.generic.in.file.handle = filehandle;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (finfo.all_info.out.size != 1) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) Incorrect resource fork size\n",
			       __location__);
		ret = false;
		smb2_util_close(tree, filehandle);
		goto done;
	}
	smb2_util_close(tree, filehandle);

done:
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_rfork_truncate(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_rfork_truncate";
	const char *rfork = BASEDIR "\\torture_rfork_truncate" AFPRESOURCE_STREAM;
	const char *rfork_content = "1234567890";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle fh1, fh2, fh3;
	union smb_setfileinfo sinfo;

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, testdirh);

	ret = torture_setup_file(mem_ctx, tree, fname, false);
	if (ret == false) {
		goto done;
	}

	ret &= write_stream(tree, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM,
			    10, 10, rfork_content);

	/* Truncate back to size 0, further access MUST return ENOENT */

	torture_comment(tctx, "(%s) truncate resource fork to size 0\n",
			__location__);

	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN;
	create.in.desired_access      = SEC_STD_READ_CONTROL | SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = fname;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create");
	fh1 = create.out.file.handle;

	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN_IF;
	create.in.desired_access      = SEC_STD_READ_CONTROL | SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = rfork;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create");
	fh2 = create.out.file.handle;

	ZERO_STRUCT(sinfo);
	sinfo.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sinfo.end_of_file_info.in.file.handle = fh2;
	sinfo.end_of_file_info.in.size = 0;
	status = smb2_setinfo_file(tree, &sinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_setinfo_file");

	/*
	 * Now check size, we should get OBJECT_NAME_NOT_FOUND (!)
	 */
	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN;
	create.in.desired_access      = SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = rfork;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done, "smb2_create");

	/*
	 * Do another open on the rfork and write to the new handle. A
	 * naive server might unlink the AppleDouble resource fork
	 * file when its truncated to 0 bytes above, so in case both
	 * open handles share the same underlying fd, the unlink would
	 * cause the below write to be lost.
	 */
	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN_IF;
	create.in.desired_access      = SEC_STD_READ_CONTROL | SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = rfork;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create");
	fh3 = create.out.file.handle;

	status = smb2_util_write(tree, fh3, "foo", 0, 3);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_util_write");

	smb2_util_close(tree, fh3);
	smb2_util_close(tree, fh2);
	smb2_util_close(tree, fh1);

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPRESOURCE_STREAM,
			   0, 3, 0, 3, "foo");
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream");

done:
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_rfork_create(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_rfork_create";
	const char *rfork = BASEDIR "\\torture_rfork_create" AFPRESOURCE_STREAM;
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle fh1;
	const char *streams[] = {
		"::$DATA"
	};
	union smb_fileinfo finfo;

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, testdirh);

	ret = torture_setup_file(mem_ctx, tree, fname, false);
	if (ret == false) {
		goto done;
	}

	torture_comment(tctx, "(%s) open rfork, should return ENOENT\n",
			__location__);

	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN;
	create.in.desired_access      = SEC_STD_READ_CONTROL | SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = rfork;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done, "smb2_create");

	torture_comment(tctx, "(%s) create resource fork\n", __location__);

	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN_IF;
	create.in.desired_access      = SEC_STD_READ_CONTROL | SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = rfork;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create");
	fh1 = create.out.file.handle;

	torture_comment(tctx, "(%s) getinfo on create handle\n",
			__location__);

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_ALL_INFORMATION;
	finfo.generic.in.file.handle = fh1;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_getinfo_file");
	if (finfo.all_info.out.size != 0) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) Incorrect resource fork size\n",
			       __location__);
		ret = false;
		smb2_util_close(tree, fh1);
		goto done;
	}

	torture_comment(tctx, "(%s) open rfork, should still return ENOENT\n",
			__location__);

	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN;
	create.in.desired_access      = SEC_STD_READ_CONTROL | SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = rfork;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done, "smb2_create");

	ret = check_stream_list(tree, tctx, fname, 1, streams, false);
	torture_assert_goto(tctx, ret == true, ret, done, "check_stream_list");

	torture_comment(tctx, "(%s) close empty created rfork, open should return ENOENT\n",
			__location__);

	ZERO_STRUCT(create);
	create.in.create_disposition  = NTCREATEX_DISP_OPEN;
	create.in.desired_access      = SEC_STD_READ_CONTROL | SEC_FILE_ALL;
	create.in.file_attributes     = FILE_ATTRIBUTE_NORMAL;
	create.in.fname               = rfork;
	create.in.share_access        = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done, "smb2_create");

done:
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_adouble_conversion(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\test_adouble_conversion";
	const char *fname_local = BASEDIR "/test_adouble_conversion";
	const char *adname_local = BASEDIR "/._test_adouble_conversion";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	const char *data = "This resource fork intentionally left blank";
	size_t datalen = strlen(data);
	const char *localdir = NULL;

	localdir = torture_setting_string(tctx, "localdir", NULL);
	if (localdir == NULL) {
		torture_skip(tctx, "Need localdir for test");
	}

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, testdirh);

	ret = torture_setup_local_file(tctx, "localdir", fname_local,
				       NULL, 0);
	if (ret == false) {
		goto done;
	}

	ret = torture_setup_local_file(tctx, "localdir", adname_local,
				       osx_adouble_w_xattr,
				       sizeof(osx_adouble_w_xattr));
	if (ret == false) {
		goto done;
	}

	torture_comment(tctx, "(%s) test OS X AppleDouble conversion\n",
	    __location__);

	ret &= check_stream(tree, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM,
			    16, datalen, 0, datalen, data);

done:
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_aapl(struct torture_context *tctx,
		      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\test_aapl";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	struct smb2_create io;
	DATA_BLOB data;
	struct smb2_create_blob *aapl = NULL;
	AfpInfo *info;
	const char *type_creator = "SMB,OLE!";
	char type_creator_buf[9];
	uint32_t aapl_cmd;
	uint32_t aapl_reply_bitmap;
	uint32_t aapl_server_caps;
	uint32_t aapl_vol_caps;
	char *model;
	struct smb2_find f;
	unsigned int count;
	union smb_search_data *d;
	uint64_t rfork_len;

	smb2_deltree(tree, BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, testdirh);

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = (NTCREATEX_SHARE_ACCESS_DELETE |
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE);
	io.in.fname = fname;

	/*
	 * Issuing an SMB2/CREATE with a suitably formed AAPL context,
	 * controls behaviour of Apple's SMB2 extensions for the whole
	 * session!
	 */

	data = data_blob_talloc(mem_ctx, NULL, 3 * sizeof(uint64_t));
	SBVAL(data.data, 0, SMB2_CRTCTX_AAPL_SERVER_QUERY);
	SBVAL(data.data, 8, (SMB2_CRTCTX_AAPL_SERVER_CAPS |
			     SMB2_CRTCTX_AAPL_VOLUME_CAPS |
			     SMB2_CRTCTX_AAPL_MODEL_INFO));
	SBVAL(data.data, 16, (SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
			      SMB2_CRTCTX_AAPL_UNIX_BASED |
			      SMB2_CRTCTX_AAPL_SUPPORTS_NFS_ACE));

	torture_comment(tctx, "Testing SMB2 create context AAPL\n");
	status = smb2_create_blob_add(tctx, &io.in.blobs, "AAPL", data);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Now check returned AAPL context
	 */
	torture_comment(tctx, "Comparing returned AAPL capabilities\n");

	aapl = smb2_create_blob_find(&io.out.blobs,
				     SMB2_CREATE_TAG_AAPL);

	if (aapl == NULL) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) unexpectedly no AAPL capabilities were returned.",
			       __location__);
		ret = false;
		goto done;
	}

	if (aapl->data.length != 50) {
		/*
		 * uint32_t CommandCode = kAAPL_SERVER_QUERY
		 * uint32_t Reserved = 0;
		 * uint64_t ReplyBitmap = kAAPL_SERVER_CAPS |
		 *                        kAAPL_VOLUME_CAPS |
		 *                        kAAPL_MODEL_INFO;
		 * uint64_t ServerCaps = kAAPL_SUPPORTS_READDIR_ATTR |
		 *                       kAAPL_SUPPORTS_OSX_COPYFILE;
		 * uint64_t VolumeCaps = kAAPL_SUPPORT_RESOLVE_ID |
		 *                       kAAPL_CASE_SENSITIVE;
		 * uint32_t Pad2 = 0;
		 * uint32_t ModelStringLen = 10;
		 * ucs2_t ModelString[5] = "Samba";
		 */
		torture_warning(tctx,
				"(%s) unexpected AAPL context length: %zd, expected 50",
				__location__, aapl->data.length);
	}

	aapl_cmd = IVAL(aapl->data.data, 0);
	if (aapl_cmd != SMB2_CRTCTX_AAPL_SERVER_QUERY) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) unexpected cmd: %d",
			       __location__, (int)aapl_cmd);
		ret = false;
		goto done;
	}

	aapl_reply_bitmap = BVAL(aapl->data.data, 8);
	if (aapl_reply_bitmap != (SMB2_CRTCTX_AAPL_SERVER_CAPS |
				  SMB2_CRTCTX_AAPL_VOLUME_CAPS |
				  SMB2_CRTCTX_AAPL_MODEL_INFO)) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) unexpected reply_bitmap: %d",
			       __location__, (int)aapl_reply_bitmap);
		ret = false;
		goto done;
	}

	aapl_server_caps = BVAL(aapl->data.data, 16);
	if (aapl_server_caps != (SMB2_CRTCTX_AAPL_UNIX_BASED |
				 SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
				 SMB2_CRTCTX_AAPL_SUPPORTS_NFS_ACE |
				 SMB2_CRTCTX_AAPL_SUPPORTS_OSX_COPYFILE)) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) unexpected server_caps: %d",
			       __location__, (int)aapl_server_caps);
		ret = false;
		goto done;
	}

	aapl_vol_caps = BVAL(aapl->data.data, 24);
	if (aapl_vol_caps != SMB2_CRTCTX_AAPL_CASE_SENSITIVE) {
		/* this will fail on a case insensitive fs ... */
		torture_warning(tctx,
				"(%s) unexpected vol_caps: %d",
				__location__, (int)aapl_vol_caps);
	}

	ret = convert_string_talloc(mem_ctx,
				    CH_UTF16LE, CH_UNIX,
				    aapl->data.data + 40, 10,
				    &model, NULL);
	if (ret == false) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) convert_string_talloc() failed",
			       __location__);
		goto done;
	}
	torture_comment(tctx, "Got server model: \"%s\"\n", model);

	/*
	 * Now that Requested AAPL extensions are enabled, setup some
	 * Mac files with metadata and resource fork
	 */
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	if (ret == false) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) torture_setup_file() failed",
			       __location__);
		goto done;
	}

	info = torture_afpinfo_new(mem_ctx);
	if (info == NULL) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) torture_afpinfo_new() failed",
			       __location__);
		ret = false;
		goto done;
	}

	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	if (ret == false) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) torture_write_afpinfo() failed",
			       __location__);
		goto done;
	}

	ret = write_stream(tree, __location__, tctx, mem_ctx,
			   fname, AFPRESOURCE_STREAM_NAME,
			   0, 3, "foo");
	if (ret == false) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) write_stream() failed",
			       __location__);
		goto done;
	}

	/*
	 * Ok, file is prepared, now call smb2/find
	 */

	ZERO_STRUCT(io);
	io.in.desired_access = SEC_RIGHTS_DIR_READ;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access = (NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE |
			      NTCREATEX_SHARE_ACCESS_DELETE);
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname = BASEDIR;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(f);
	f.in.file.handle	= io.out.file.handle;
	f.in.pattern		= "test_aapl";
	f.in.continue_flags	= SMB2_CONTINUE_FLAG_SINGLE;
	f.in.max_response_size	= 0x1000;
	f.in.level              = SMB2_FIND_ID_BOTH_DIRECTORY_INFO;

	status = smb2_find_level(tree, tree, &f, &count, &d);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (strcmp(d[0].id_both_directory_info.name.s, "test_aapl") != 0) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) write_stream() failed",
			       __location__);
		ret = false;
		goto done;
	}

	if (d[0].id_both_directory_info.short_name.private_length != 24) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) bad short_name length %" PRIu32 ", expected 24",
			       __location__, d[0].id_both_directory_info.short_name.private_length);
		ret = false;
		goto done;
	}

	torture_comment(tctx, "short_name buffer:\n");
	dump_data(0, d[0].id_both_directory_info.short_name_buf, 24);

	/*
	 * Extract data as specified by the AAPL extension:
	 * - ea_size contains max_access
	 * - short_name contains resource fork length + FinderInfo
	 * - reserved2 contains the unix mode
	 */
	torture_comment(tctx, "mac_access: %" PRIx32 "\n",
			d[0].id_both_directory_info.ea_size);

	rfork_len = BVAL(d[0].id_both_directory_info.short_name_buf, 0);
	if (rfork_len != 3) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) expected resource fork length 3, got: %" PRIu64,
			       __location__, rfork_len);
		ret = false;
		goto done;
	}

	memcpy(type_creator_buf, d[0].id_both_directory_info.short_name_buf + 8, 8);
	type_creator_buf[8] = 0;
	if (strcmp(type_creator, type_creator_buf) != 0) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) expected type/creator \"%s\" , got: %s",
			       __location__, type_creator, type_creator_buf);
		ret = false;
		goto done;
	}

done:
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static uint64_t patt_hash(uint64_t off)
{
	return off;
}

static bool write_pattern(struct torture_context *torture,
			  struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
			  struct smb2_handle h, uint64_t off, uint64_t len,
			  uint64_t patt_off)
{
	NTSTATUS status;
	uint64_t i;
	uint8_t *buf;
	uint64_t io_sz = MIN(1024 * 64, len);

	if (len == 0) {
		return true;
	}

	torture_assert(torture, (len % 8) == 0, "invalid write len");

	buf = talloc_zero_size(mem_ctx, io_sz);
	torture_assert(torture, (buf != NULL), "no memory for file data buf");

	while (len > 0) {
		for (i = 0; i <= io_sz - 8; i += 8) {
			SBVAL(buf, i, patt_hash(patt_off));
			patt_off += 8;
		}

		status = smb2_util_write(tree, h,
					 buf, off, io_sz);
		torture_assert_ntstatus_ok(torture, status, "file write");

		len -= io_sz;
		off += io_sz;
	}

	talloc_free(buf);

	return true;
}

static bool check_pattern(struct torture_context *torture,
			  struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
			  struct smb2_handle h, uint64_t off, uint64_t len,
			  uint64_t patt_off)
{
	if (len == 0) {
		return true;
	}

	torture_assert(torture, (len % 8) == 0, "invalid read len");

	while (len > 0) {
		uint64_t i;
		struct smb2_read r;
		NTSTATUS status;
		uint64_t io_sz = MIN(1024 * 64, len);

		ZERO_STRUCT(r);
		r.in.file.handle = h;
		r.in.length      = io_sz;
		r.in.offset      = off;
		status = smb2_read(tree, mem_ctx, &r);
		torture_assert_ntstatus_ok(torture, status, "read");

		torture_assert_u64_equal(torture, r.out.data.length, io_sz,
					 "read data len mismatch");

		for (i = 0; i <= io_sz - 8; i += 8, patt_off += 8) {
			uint64_t data = BVAL(r.out.data.data, i);
			torture_assert_u64_equal(torture, data, patt_hash(patt_off),
						 talloc_asprintf(torture, "read data "
								 "pattern bad at %llu\n",
								 (unsigned long long)off + i));
		}
		talloc_free(r.out.data.data);
		len -= io_sz;
		off += io_sz;
	}

	return true;
}

static bool test_setup_open(struct torture_context *torture,
			    struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
			    const char *fname,
			    struct smb2_handle *fh,
			    uint32_t desired_access,
			    uint32_t file_attributes)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.desired_access = desired_access;
	io.in.file_attributes = file_attributes;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	if (file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	}
	io.in.fname = fname;

	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "file create");

	*fh = io.out.file.handle;

	return true;
}

static bool test_setup_create_fill(struct torture_context *torture,
				   struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
				   const char *fname,
				   struct smb2_handle *fh,
				   uint64_t size,
				   uint32_t desired_access,
				   uint32_t file_attributes)
{
	bool ok;

	ok = test_setup_open(torture, tree, mem_ctx,
			     fname,
			     fh,
			     desired_access,
			     file_attributes);
	torture_assert(torture, ok, "file open");

	if (size > 0) {
		ok = write_pattern(torture, tree, mem_ctx, *fh, 0, size, 0);
		torture_assert(torture, ok, "write pattern");
	}
	return true;
}

static bool test_setup_copy_chunk(struct torture_context *torture,
				  struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
				  uint32_t nchunks,
				  struct smb2_handle *src_h,
				  uint64_t src_size,
				  uint32_t src_desired_access,
				  struct smb2_handle *dest_h,
				  uint64_t dest_size,
				  uint32_t dest_desired_access,
				  struct srv_copychunk_copy *cc_copy,
				  union smb_ioctl *io)
{
	struct req_resume_key_rsp res_key;
	bool ok;
	NTSTATUS status;
	enum ndr_err_code ndr_ret;

	ok = test_setup_create_fill(torture, tree, mem_ctx, FNAME_CC_SRC,
				    src_h, src_size, src_desired_access,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "src file create fill");

	ok = test_setup_create_fill(torture, tree, mem_ctx, FNAME_CC_DST,
				    dest_h, dest_size, dest_desired_access,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "dest file create fill");

	ZERO_STRUCTPN(io);
	io->smb2.level = RAW_IOCTL_SMB2;
	io->smb2.in.file.handle = *src_h;
	io->smb2.in.function = FSCTL_SRV_REQUEST_RESUME_KEY;
	/* Allow for Key + ContextLength + Context */
	io->smb2.in.max_response_size = 32;
	io->smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, mem_ctx, &io->smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_REQUEST_RESUME_KEY");

	ndr_ret = ndr_pull_struct_blob(&io->smb2.out.out, mem_ctx, &res_key,
			(ndr_pull_flags_fn_t)ndr_pull_req_resume_key_rsp);

	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_req_resume_key_rsp");

	ZERO_STRUCTPN(io);
	io->smb2.level = RAW_IOCTL_SMB2;
	io->smb2.in.file.handle = *dest_h;
	io->smb2.in.function = FSCTL_SRV_COPYCHUNK;
	io->smb2.in.max_response_size = sizeof(struct srv_copychunk_rsp);
	io->smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	ZERO_STRUCTPN(cc_copy);
	memcpy(cc_copy->source_key, res_key.resume_key, ARRAY_SIZE(cc_copy->source_key));
	cc_copy->chunk_count = nchunks;
	cc_copy->chunks = talloc_zero_array(mem_ctx, struct srv_copychunk, nchunks);
	torture_assert(torture, (cc_copy->chunks != NULL), "no memory for chunks");

	return true;
}


static bool check_copy_chunk_rsp(struct torture_context *torture,
				 struct srv_copychunk_rsp *cc_rsp,
				 uint32_t ex_chunks_written,
				 uint32_t ex_chunk_bytes_written,
				 uint32_t ex_total_bytes_written)
{
	torture_assert_int_equal(torture, cc_rsp->chunks_written,
				 ex_chunks_written, "num chunks");
	torture_assert_int_equal(torture, cc_rsp->chunk_bytes_written,
				 ex_chunk_bytes_written, "chunk bytes written");
	torture_assert_int_equal(torture, cc_rsp->total_bytes_written,
				 ex_total_bytes_written, "chunk total bytes");
	return true;
}

static bool neg_aapl_copyfile(struct torture_context *tctx,
			      struct smb2_tree *tree,
			      uint64_t flags)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = "aapl";
	NTSTATUS status;
	struct smb2_create io;
	DATA_BLOB data;
	struct smb2_create_blob *aapl = NULL;
	uint32_t aapl_cmd;
	uint32_t aapl_reply_bitmap;
	uint32_t aapl_server_caps;
	bool ret = true;

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = (NTCREATEX_SHARE_ACCESS_DELETE |
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE);
	io.in.fname = fname;

	data = data_blob_talloc(mem_ctx, NULL, 3 * sizeof(uint64_t));
	SBVAL(data.data, 0, SMB2_CRTCTX_AAPL_SERVER_QUERY);
	SBVAL(data.data, 8, (SMB2_CRTCTX_AAPL_SERVER_CAPS));
	SBVAL(data.data, 16, flags);

	status = smb2_create_blob_add(tctx, &io.in.blobs, "AAPL", data);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	aapl = smb2_create_blob_find(&io.out.blobs,
				     SMB2_CREATE_TAG_AAPL);
	if (aapl == NULL) {
		ret = false;
		goto done;

	}
	if (aapl->data.length < 24) {
		ret = false;
		goto done;
	}

	aapl_cmd = IVAL(aapl->data.data, 0);
	if (aapl_cmd != SMB2_CRTCTX_AAPL_SERVER_QUERY) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) unexpected cmd: %d",
			       __location__, (int)aapl_cmd);
		ret = false;
		goto done;
	}

	aapl_reply_bitmap = BVAL(aapl->data.data, 8);
	if (!(aapl_reply_bitmap & SMB2_CRTCTX_AAPL_SERVER_CAPS)) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) unexpected reply_bitmap: %d",
			       __location__, (int)aapl_reply_bitmap);
		ret = false;
		goto done;
	}

	aapl_server_caps = BVAL(aapl->data.data, 16);
	if (!(aapl_server_caps & flags)) {
		torture_result(tctx, TORTURE_FAIL,
			       "(%s) unexpected server_caps: %d",
			       __location__, (int)aapl_server_caps);
		ret = false;
		goto done;
	}

done:
	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_unlink(tree, "aapl");
	talloc_free(mem_ctx);
	return ret;
}

static bool test_copyfile(struct torture_context *torture,
			  struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl io;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;

	/*
	 * First test a copy_chunk with a 0 chunk count without having
	 * enabled this via AAPL. The request must not fail and the
	 * copied length in the response must be 0. This is verified
	 * against Windows 2008r2.
	 */

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   0, /* 0 chunks, copyfile semantics */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
				   &cc_copy,
				   &io);
	if (!ok) {
		torture_fail_goto(torture, done, "setup copy chunk error");
	}

	ndr_ret = ndr_push_struct_blob(&io.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &io.smb2);
	torture_assert_ntstatus_ok_goto(torture, status, ok, done, "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&io.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  0,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  0); /* total bytes written */
	if (!ok) {
		torture_fail_goto(torture, done, "bad copy chunk response data");
	}

	/*
	 * Now enable AAPL copyfile and test again, the file and the
	 * stream must be copied by the server.
	 */
	ok = neg_aapl_copyfile(torture, tree,
			       SMB2_CRTCTX_AAPL_SUPPORTS_OSX_COPYFILE);
	if (!ok) {
		torture_skip_goto(torture, done, "missing AAPL copyfile");
		goto done;
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	smb2_util_unlink(tree, FNAME_CC_SRC);
	smb2_util_unlink(tree, FNAME_CC_DST);

	ok = torture_setup_file(tmp_ctx, tree, FNAME_CC_SRC, false);
	if (!ok) {
		torture_fail(torture, "setup file error");
	}
	ok = write_stream(tree, __location__, torture, tmp_ctx,
			    FNAME_CC_SRC, AFPRESOURCE_STREAM,
			    10, 10, "1234567890");
	if (!ok) {
		torture_fail(torture, "setup stream error");
	}

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   0, /* 0 chunks, copyfile semantics */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
				   &cc_copy,
				   &io);
	if (!ok) {
		torture_fail_goto(torture, done, "setup copy chunk error");
	}

	ndr_ret = ndr_push_struct_blob(&io.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &io.smb2);
	torture_assert_ntstatus_ok_goto(torture, status, ok, done, "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&io.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  0,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  4096); /* total bytes written */
	if (!ok) {
		torture_fail_goto(torture, done, "bad copy chunk response data");
	}

	ok = test_setup_open(torture, tree, tmp_ctx, FNAME_CC_DST, &dest_h,
			     SEC_FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL);
	if (!ok) {
		torture_fail_goto(torture, done,"open failed");
	}
	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		torture_fail_goto(torture, done, "inconsistent file data");
	}

	ok = check_stream(tree, __location__, torture, tmp_ctx,
			    FNAME_CC_DST, AFPRESOURCE_STREAM,
			    0, 20, 10, 10, "1234567890");
	if (!ok) {
		torture_fail_goto(torture, done, "inconsistent stream data");
	}

done:
	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	smb2_util_unlink(tree, FNAME_CC_SRC);
	smb2_util_unlink(tree, FNAME_CC_DST);
	talloc_free(tmp_ctx);
	return true;
}

static bool check_stream_list(struct smb2_tree *tree,
			      struct torture_context *tctx,
			      const char *fname,
			      int num_exp,
			      const char **exp,
			      bool is_dir)
{
	bool ret = true;
	union smb_fileinfo finfo;
	NTSTATUS status;
	int i;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	char **exp_sort;
	struct stream_struct *stream_sort;
	struct smb2_create create;
	struct smb2_handle h;

	ZERO_STRUCT(h);
	torture_assert_goto(tctx, tmp_ctx != NULL, ret, done, "talloc_new failed");

	ZERO_STRUCT(create);
	create.in.fname = fname;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.create_options = is_dir ? NTCREATEX_OPTIONS_DIRECTORY : 0;
	create.in.file_attributes = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
	status = smb2_create(tree, tmp_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create");
	h = create.out.file.handle;

	finfo.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	finfo.generic.in.file.handle = h;

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get stream info");

	smb2_util_close(tree, h);

	torture_assert_int_equal_goto(tctx, finfo.stream_info.out.num_streams, num_exp,
				      ret, done, "stream count");

	if (num_exp == 0) {
		TALLOC_FREE(tmp_ctx);
		goto done;
	}

	exp_sort = talloc_memdup(tmp_ctx, exp, num_exp * sizeof(*exp));
	torture_assert_goto(tctx, exp_sort != NULL, ret, done, __location__);

	TYPESAFE_QSORT(exp_sort, num_exp, qsort_string);

	stream_sort = talloc_memdup(tmp_ctx, finfo.stream_info.out.streams,
				    finfo.stream_info.out.num_streams *
				    sizeof(*stream_sort));
	torture_assert_goto(tctx, stream_sort != NULL, ret, done, __location__);

	TYPESAFE_QSORT(stream_sort, finfo.stream_info.out.num_streams, qsort_stream);

	for (i=0; i<num_exp; i++) {
		torture_comment(tctx, "i[%d] exp[%s] got[%s]\n",
				i, exp_sort[i], stream_sort[i].stream_name.s);
		torture_assert_str_equal_goto(tctx, stream_sort[i].stream_name.s, exp_sort[i],
					      ret, done, "stream name");
	}

done:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/*
  test stream names
*/
static bool test_stream_names(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	struct smb2_create create;
	struct smb2_handle h;
	const char *fname = BASEDIR "\\stream_names.txt";
	const char *sname1;
	bool ret;
	/* UTF8 private use are starts at 0xef 0x80 0x80 (0xf000) */
	const char *streams[] = {
		":foo" "\xef\x80\xa2" "bar:$DATA", /* "foo:bar:$DATA" */
		":bar" "\xef\x80\xa2" "baz:$DATA", /* "bar:baz:$DATA" */
		"::$DATA"
	};
	const char *localdir = NULL;

	localdir = torture_setting_string(tctx, "localdir", NULL);
	if (localdir == NULL) {
		torture_skip(tctx, "Need localdir for test");
	}

	sname1 = talloc_asprintf(mem_ctx, "%s%s", fname, streams[0]);

	/* clean slate ...*/
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, fname);
	smb2_deltree(tree, BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, h);

	torture_comment(tctx, "(%s) testing stream names\n", __location__);
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_FILE_WRITE_DATA;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	create.in.create_disposition = NTCREATEX_DISP_CREATE;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname1;

	status = smb2_create(tree, mem_ctx, &create);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, create.out.file.handle);

	ret = torture_setup_local_xattr(tctx, "localdir", BASEDIR "/stream_names.txt",
					"user.DosStream.bar:baz:$DATA",
					"data", strlen("data"));
	CHECK_VALUE(ret, true);

	ret = check_stream_list(tree, tctx, fname, 3, streams, false);
	CHECK_VALUE(ret, true);

done:
	status = smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);

	return ret;
}

/* Renaming a directory with open file, should work for OS X AAPL clients */
static bool test_rename_dir_openfile(struct torture_context *torture,
				     struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	struct smb2_handle d1, h1;
	const char *renamedir = BASEDIR "-new";
	bool server_is_osx = torture_setting_bool(torture, "osx", false);

	smb2_deltree(tree, BASEDIR);
	smb2_util_rmdir(tree, BASEDIR);
	smb2_deltree(tree, renamedir);

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = 0x0017019f;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree, torture, &(io.smb2));
	torture_assert_ntstatus_ok(torture, status, "smb2_create dir");
	d1 = io.smb2.out.file.handle;

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = 0x0017019f;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree, torture, &(io.smb2));
	torture_assert_ntstatus_ok(torture, status, "smb2_create file");
	h1 = io.smb2.out.file.handle;

	if (!server_is_osx) {
		torture_comment(torture, "Renaming directory without AAPL, must fail\n");

		ZERO_STRUCT(sinfo);
		sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
		sinfo.rename_information.in.file.handle = d1;
		sinfo.rename_information.in.overwrite = 0;
		sinfo.rename_information.in.root_fid = 0;
		sinfo.rename_information.in.new_name = renamedir;
		status = smb2_setinfo_file(tree, &sinfo);

		torture_assert_ntstatus_equal(torture, status,
					      NT_STATUS_ACCESS_DENIED,
					      "smb2_setinfo_file");

		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = d1;
		status = smb2_close(tree, &(cl.smb2));
		torture_assert_ntstatus_ok(torture, status, "smb2_close");
		ZERO_STRUCT(d1);
	}

	torture_comment(torture, "Enabling AAPL\n");

	ret = enable_aapl(torture, tree);
	torture_assert(torture, ret == true, "enable_aapl failed");

	torture_comment(torture, "Renaming directory with AAPL\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = 0x0017019f;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree, torture, &(io.smb2));
	torture_assert_ntstatus_ok(torture, status, "smb2_create dir");
	d1 = io.smb2.out.file.handle;

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = d1;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name = renamedir;

	status = smb2_setinfo_file(tree, &sinfo);
	torture_assert_ntstatus_ok(torture, status, "smb2_setinfo_file");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = d1;
	status = smb2_close(tree, &(cl.smb2));
	torture_assert_ntstatus_ok(torture, status, "smb2_close");
	ZERO_STRUCT(d1);

	cl.smb2.in.file.handle = h1;
	status = smb2_close(tree, &(cl.smb2));
	torture_assert_ntstatus_ok(torture, status, "smb2_close");
	ZERO_STRUCT(h1);

	torture_comment(torture, "Cleaning up\n");

	if (h1.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = h1;
		status = smb2_close(tree, &(cl.smb2));
	}

	smb2_util_unlink(tree, BASEDIR "\\file.txt");
	smb2_util_unlink(tree, BASEDIR "-new\\file.txt");
	smb2_deltree(tree, renamedir);
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_afpinfo_enoent(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create create;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *sname = BASEDIR "\\file" AFPINFO_STREAM_NAME;

	torture_comment(tctx, "Opening file without AFP_AfpInfo\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	torture_comment(tctx, "Opening not existing AFP_AfpInfo\n");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE; /* stat open */
	create.in.fname = sname;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Got unexpected AFP_AfpInfo stream");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

static bool test_create_delete_on_close(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create create;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *sname = BASEDIR "\\file" AFPINFO_STREAM_NAME;
	const char *type_creator = "SMB,OLE!";
	AfpInfo *info = NULL;
	const char *streams_basic[] = {
		"::$DATA"
	};
	const char *streams_afpinfo[] = {
		"::$DATA",
		AFPINFO_STREAM
	};

	torture_assert_goto(tctx, mem_ctx != NULL, ret, done, "talloc_new");

	torture_comment(tctx, "Checking whether create with delete-on-close work with AFP_AfpInfo\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	torture_comment(tctx, "Opening not existing AFP_AfpInfo\n");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE; /* stat open */
	create.in.fname = sname;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Got unexpected AFP_AfpInfo stream");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Got unexpected AFP_AfpInfo stream");

	ret = check_stream_list(tree, tctx, fname, 1, streams_basic, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	torture_comment(tctx, "Deleting AFP_AfpInfo via create with delete-on-close\n");

	info = torture_afpinfo_new(mem_ctx);
	torture_assert_goto(tctx, info != NULL, ret, done, "torture_afpinfo_new failed");

	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_write_afpinfo failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   0, 60, 16, 8, type_creator);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad type/creator in AFP_AfpInfo");

	ret = check_stream_list(tree, tctx, fname, 2, streams_afpinfo, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE | SEC_STD_SYNCHRONIZE | SEC_STD_DELETE;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;
	smb2_util_close(tree, h1);

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Got unexpected AFP_AfpInfo stream");

	ret = check_stream_list(tree, tctx, fname, 1, streams_basic, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

static bool test_setinfo_delete_on_close(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create create;
	union smb_setfileinfo sfinfo;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *sname = BASEDIR "\\file" AFPINFO_STREAM_NAME;
	const char *type_creator = "SMB,OLE!";
	AfpInfo *info = NULL;
	const char *streams_basic[] = {
		"::$DATA"
	};

	torture_assert_goto(tctx, mem_ctx != NULL, ret, done, "talloc_new");

	torture_comment(tctx, "Deleting AFP_AfpInfo via setinfo with delete-on-close\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	info = torture_afpinfo_new(mem_ctx);
	torture_assert_goto(tctx, info != NULL, ret, done, "torture_afpinfo_new failed");
	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_write_afpinfo failed");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE | SEC_STD_SYNCHRONIZE | SEC_STD_DELETE;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;

	/* Delete stream via setinfo delete-on-close */
	ZERO_STRUCT(sfinfo);
	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set delete-on-close failed");

	smb2_util_close(tree, h1);

	ret = check_stream_list(tree, tctx, fname, 1, streams_basic, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Got unexpected AFP_AfpInfo stream");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

static bool test_setinfo_eof(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create create;
	union smb_setfileinfo sfinfo;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *sname = BASEDIR "\\file" AFPINFO_STREAM_NAME;
	const char *type_creator = "SMB,OLE!";
	AfpInfo *info = NULL;
	const char *streams_afpinfo[] = {
		"::$DATA",
		AFPINFO_STREAM
	};

	torture_assert_goto(tctx, mem_ctx != NULL, ret, done, "talloc_new");

	torture_comment(tctx, "Set AFP_AfpInfo EOF to 61, 1 and 0\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	info = torture_afpinfo_new(mem_ctx);
	torture_assert_goto(tctx, info != NULL, ret, done, "torture_afpinfo_new failed");
	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_write_afpinfo failed");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;

	torture_comment(tctx, "Set AFP_AfpInfo EOF to 61\n");

	/* Test setinfo end-of-file info */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.in.file.handle = h1;
	sfinfo.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfinfo.position_information.in.position = 61;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ALLOTTED_SPACE_EXCEEDED,
					   ret, done, "set eof 61 failed");

	torture_comment(tctx, "Set AFP_AfpInfo EOF to 1\n");

	/* Truncation returns success, but has no effect */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.in.file.handle = h1;
	sfinfo.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfinfo.position_information.in.position = 1;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status,
					ret, done, "set eof 1 failed");
	smb2_util_close(tree, h1);

	ret = check_stream_list(tree, tctx, fname, 2, streams_afpinfo, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   0, 60, 16, 8, type_creator);
	torture_assert_goto(tctx, ret == true, ret, done, "FinderInfo changed");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;

	/*
	 * Delete stream via setinfo end-of-file info to 0, should
	 * return success but stream MUST NOT deleted
	 */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.in.file.handle = h1;
	sfinfo.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfinfo.position_information.in.position = 0;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set eof 0 failed");

	smb2_util_close(tree, h1);

	ret = check_stream_list(tree, tctx, fname, 2, streams_afpinfo, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			   0, 60, 16, 8, type_creator);
	torture_assert_goto(tctx, ret == true, ret, done, "FinderInfo changed");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

static bool test_afpinfo_all0(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *type_creator = "SMB,OLE!";
	AfpInfo *info = NULL;
	const char *streams_basic[] = {
		"::$DATA"
	};
	const char *streams_afpinfo[] = {
		"::$DATA",
		AFPINFO_STREAM
	};

	torture_assert_goto(tctx, mem_ctx != NULL, ret, done, "talloc_new");

	torture_comment(tctx, "Write all 0 to AFP_AfpInfo and see what happens\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	info = torture_afpinfo_new(mem_ctx);
	torture_assert_goto(tctx, info != NULL, ret, done, "torture_afpinfo_new failed");
	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_write_afpinfo failed");

	ret = check_stream_list(tree, tctx, fname, 2, streams_afpinfo, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	/* Write all 0 to AFP_AfpInfo */
	memset(info->afpi_FinderInfo, 0, AFP_FinderSize);
	ret = torture_write_afpinfo(tree, tctx, mem_ctx, fname, info);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_write_afpinfo failed");

	ret = check_stream_list(tree, tctx, fname, 1, streams_basic, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

static bool test_create_delete_on_close_resource(struct torture_context *tctx,
						 struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create create;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *sname = BASEDIR "\\file" AFPRESOURCE_STREAM_NAME;
	const char *streams_basic[] = {
		"::$DATA"
	};
	const char *streams_afpresource[] = {
		"::$DATA",
		AFPRESOURCE_STREAM
	};

	torture_assert_goto(tctx, mem_ctx != NULL, ret, done, "talloc_new");

	torture_comment(tctx, "Checking whether create with delete-on-close is ignored for AFP_AfpResource\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok(tctx, status, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	torture_comment(tctx, "Opening not existing AFP_AfpResource\n");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE; /* stat open */
	create.in.fname = sname;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Got unexpected AFP_AfpResource stream");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Got unexpected AFP_AfpResource stream");

	ret = check_stream_list(tree, tctx, fname, 1, streams_basic, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	torture_comment(tctx, "Trying to delete AFP_AfpResource via create with delete-on-close\n");

	ret = write_stream(tree, __location__, tctx, mem_ctx,
			   fname, AFPRESOURCE_STREAM_NAME,
			   0, 10, "1234567890");
	torture_assert_goto(tctx, ret == true, ret, done, "Writing to AFP_AfpResource failed");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPRESOURCE_STREAM_NAME,
			   0, 10, 0, 10, "1234567890");
	torture_assert_goto(tctx, ret == true, ret, done, "Bad content from AFP_AfpResource");

	ret = check_stream_list(tree, tctx, fname, 2, streams_afpresource, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE | SEC_STD_SYNCHRONIZE | SEC_STD_DELETE;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;
	smb2_util_close(tree, h1);

	ret = check_stream_list(tree, tctx, fname, 2, streams_afpresource, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ret = check_stream(tree, __location__, tctx, mem_ctx, fname, AFPRESOURCE_STREAM_NAME,
			   0, 10, 0, 10, "1234567890");
	torture_assert_goto(tctx, ret == true, ret, done, "Bad content from AFP_AfpResource");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

static bool test_setinfo_delete_on_close_resource(struct torture_context *tctx,
						  struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create create;
	union smb_setfileinfo sfinfo;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *sname = BASEDIR "\\file" AFPRESOURCE_STREAM_NAME;
	const char *streams_afpresource[] = {
		"::$DATA",
		AFPRESOURCE_STREAM
	};

	torture_assert_goto(tctx, mem_ctx != NULL, ret, done, "talloc_new");

	torture_comment(tctx, "Trying to delete AFP_AfpResource via setinfo with delete-on-close\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	ret = write_stream(tree, __location__, tctx, mem_ctx,
			   fname, AFPRESOURCE_STREAM_NAME,
			   10, 10, "1234567890");
	torture_assert_goto(tctx, ret == true, ret, done, "Writing to AFP_AfpResource failed");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_READ_ATTRIBUTE | SEC_STD_SYNCHRONIZE | SEC_STD_DELETE;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;

	/* Try to delete stream via setinfo delete-on-close */
	ZERO_STRUCT(sfinfo);
	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set delete-on-close failed");

	smb2_util_close(tree, h1);

	ret = check_stream_list(tree, tctx, fname, 2, streams_afpresource, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Got unexpected AFP_AfpResource stream");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

static bool test_setinfo_eof_resource(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create create;
	union smb_setfileinfo sfinfo;
	union smb_fileinfo finfo;
	struct smb2_handle h1;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\file";
	const char *sname = BASEDIR "\\file" AFPRESOURCE_STREAM_NAME;
	const char *streams_basic[] = {
		"::$DATA"
	};

	torture_assert_goto(tctx, mem_ctx != NULL, ret, done, "talloc_new");

	torture_comment(tctx, "Set AFP_AfpResource EOF to 1 and 0\n");

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir");
	smb2_util_close(tree, h1);
	ret = torture_setup_file(mem_ctx, tree, fname, false);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_setup_file");

	ret = write_stream(tree, __location__, tctx, mem_ctx,
			   fname, AFPRESOURCE_STREAM_NAME,
			   10, 10, "1234567890");
	torture_assert_goto(tctx, ret == true, ret, done, "Writing to AFP_AfpResource failed");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;

	torture_comment(tctx, "Set AFP_AfpResource EOF to 1\n");

	/* Test setinfo end-of-file info */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.in.file.handle = h1;
	sfinfo.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfinfo.position_information.in.position = 1;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status,
					ret, done, "set eof 1 failed");

 	smb2_util_close(tree, h1);

	/* Check size == 1 */
	ZERO_STRUCT(create);
	create.in.fname = sname;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	finfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_getinfo_file failed");

	smb2_util_close(tree, h1);

	torture_assert_goto(tctx, finfo.all_info.out.size == 1, ret, done, "size != 1");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed");

	h1 = create.out.file.handle;

	/*
	 * Delete stream via setinfo end-of-file info to 0, this
	 * should delete the stream.
	 */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.in.file.handle = h1;
	sfinfo.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfinfo.position_information.in.position = 0;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set eof 0 failed");

	smb2_util_close(tree, h1);

	ret = check_stream_list(tree, tctx, fname, 1, streams_basic, false);
	torture_assert_goto(tctx, ret == true, ret, done, "Bad streams");

	ZERO_STRUCT(create);
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.desired_access = SEC_FILE_ALL;
	create.in.fname = sname;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;

	status = smb2_create(tree, mem_ctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "smb2_create failed");

done:
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, BASEDIR);
	return ret;
}

/*
 * Note: This test depends on "vfs objects = catia fruit streams_xattr".  For
 * some tests torture must be run on the host it tests and takes an additional
 * argument with the local path to the share:
 * "--option=torture:localdir=<SHAREPATH>".
 *
 * When running against an OS X SMB server add "--option=torture:osx=true"
 */
struct torture_suite *torture_vfs_fruit(void)
{
	struct torture_suite *suite = torture_suite_create(
		talloc_autofree_context(), "fruit");

	suite->description = talloc_strdup(suite, "vfs_fruit tests");

	torture_suite_add_1smb2_test(suite, "copyfile", test_copyfile);
	torture_suite_add_1smb2_test(suite, "read netatalk metadata", test_read_netatalk_metadata);
	torture_suite_add_1smb2_test(suite, "read metadata", test_read_afpinfo);
	torture_suite_add_1smb2_test(suite, "write metadata", test_write_atalk_metadata);
	torture_suite_add_1smb2_test(suite, "resource fork IO", test_write_atalk_rfork_io);
	torture_suite_add_1smb2_test(suite, "OS X AppleDouble file conversion", test_adouble_conversion);
	torture_suite_add_1smb2_test(suite, "SMB2/CREATE context AAPL", test_aapl);
	torture_suite_add_1smb2_test(suite, "stream names", test_stream_names);
	torture_suite_add_1smb2_test(suite, "truncate resource fork to 0 bytes", test_rfork_truncate);
	torture_suite_add_1smb2_test(suite, "opening and creating resource fork", test_rfork_create);
	torture_suite_add_1smb2_test(suite, "rename_dir_openfile", test_rename_dir_openfile);
	torture_suite_add_1smb2_test(suite, "File without AFP_AfpInfo", test_afpinfo_enoent);
	torture_suite_add_1smb2_test(suite, "create delete-on-close AFP_AfpInfo", test_create_delete_on_close);
	torture_suite_add_1smb2_test(suite, "setinfo delete-on-close AFP_AfpInfo", test_setinfo_delete_on_close);
	torture_suite_add_1smb2_test(suite, "setinfo eof AFP_AfpInfo", test_setinfo_eof);
	torture_suite_add_1smb2_test(suite, "delete AFP_AfpInfo by writing all 0", test_afpinfo_all0);
	torture_suite_add_1smb2_test(suite, "create delete-on-close AFP_AfpResource", test_create_delete_on_close_resource);
	torture_suite_add_1smb2_test(suite, "setinfo delete-on-close AFP_AfpResource", test_setinfo_delete_on_close_resource);
	torture_suite_add_1smb2_test(suite, "setinfo eof AFP_AfpResource", test_setinfo_eof_resource);

	return suite;
}
