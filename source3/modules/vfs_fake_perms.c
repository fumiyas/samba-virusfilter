/* 
 * Fake Perms VFS module.  Implements passthrough operation of all VFS
 * calls to disk functions, except for file permissions, which are now
 * mode 0700 for the current uid/gid.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Andrew Bartlett, 2002
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static int fake_perms_stat(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname)
{
	int ret;

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	if (ret != 0) {
		return ret;
	}

	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		smb_fname->st.st_ex_mode = S_IFDIR | S_IRWXU;
	} else {
		smb_fname->st.st_ex_mode = S_IRWXU;
	}

	if (handle->conn->session_info != NULL) {
		struct security_unix_token *utok;

		utok = handle->conn->session_info->unix_token;
		smb_fname->st.st_ex_uid = utok->uid;
		smb_fname->st.st_ex_gid = utok->gid;
	} else {
		/*
		 * We have an artificial connection for dfs for example. It
		 * sucks, but the current uid/gid is the best we have.
		 */
		smb_fname->st.st_ex_uid = geteuid();
		smb_fname->st.st_ex_gid = getegid();
	}

	return ret;
}

static int fake_perms_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int ret;

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret != 0) {
		return ret;
	}

	if (S_ISDIR(sbuf->st_ex_mode)) {
		sbuf->st_ex_mode = S_IFDIR | S_IRWXU;
	} else {
		sbuf->st_ex_mode = S_IRWXU;
	}
	if (handle->conn->session_info != NULL) {
		struct security_unix_token *utok;

		utok = handle->conn->session_info->unix_token;
		sbuf->st_ex_uid = utok->uid;
		sbuf->st_ex_gid = utok->gid;
	} else {
		/*
		 * We have an artificial connection for dfs for example. It
		 * sucks, but the current uid/gid is the best we have.
		 */
		sbuf->st_ex_uid = geteuid();
		sbuf->st_ex_gid = getegid();
	}

	return ret;
}

static struct vfs_fn_pointers vfs_fake_perms_fns = {
	.stat_fn = fake_perms_stat,
	.fstat_fn = fake_perms_fstat
};

NTSTATUS vfs_fake_perms_init(void);
NTSTATUS vfs_fake_perms_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "fake_perms",
				&vfs_fake_perms_fns);
}
