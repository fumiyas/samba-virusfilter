/* 
 * AppleTalk VFS module for Samba-3.x
 *
 * Copyright (C) Alexei Kotovich, 2002
 * Copyright (C) Stefan (metze) Metzmacher, 2003
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define APPLEDOUBLE	".AppleDouble"
#define ADOUBLEMODE	0777

/* atalk functions */

static int atalk_build_paths(TALLOC_CTX *ctx, const char *path,
			     const char *fname,
			     char **adbl_path, char **orig_path,
			     SMB_STRUCT_STAT *adbl_info,
			     SMB_STRUCT_STAT *orig_info);

static int atalk_unlink_file(const char *path);

static int atalk_get_path_ptr(char *path)
{
	int i   = 0;
	int ptr = 0;
	
	for (i = 0; path[i]; i ++) {
		if (path[i] == '/')
			ptr = i;
		/* get out some 'spam';) from win32's file name */
		else if (path[i] == ':') {
			path[i] = '\0';
			break;
		}
	}
	
	return ptr;
}

static int atalk_build_paths(TALLOC_CTX *ctx, const char *path,
			     const char *fname,
			     char **adbl_path, char **orig_path,
			     SMB_STRUCT_STAT *adbl_info,
			     SMB_STRUCT_STAT *orig_info)
{
	int ptr0 = 0;
	int ptr1 = 0;
	char *dname = 0;
	char *name  = 0;

	if (!ctx || !path || !fname || !adbl_path || !orig_path ||
		!adbl_info || !orig_info)
		return -1;
#if 0
	DEBUG(3, ("ATALK: PATH: %s[%s]\n", path, fname));
#endif
	if (strstr_m(path, APPLEDOUBLE) || strstr_m(fname, APPLEDOUBLE)) {
		DEBUG(3, ("ATALK: path %s[%s] already contains %s\n", path, fname, APPLEDOUBLE));
		return -1;
	}

	if (fname[0] == '.') ptr0 ++;
	if (fname[1] == '/') ptr0 ++;

	*orig_path = talloc_asprintf(ctx, "%s/%s", path, &fname[ptr0]);

	/* get pointer to last '/' */
	ptr1 = atalk_get_path_ptr(*orig_path);

	sys_lstat(*orig_path, orig_info, false);

	if (S_ISDIR(orig_info->st_ex_mode)) {
		*adbl_path = talloc_asprintf(ctx, "%s/%s/%s/", 
		  path, &fname[ptr0], APPLEDOUBLE);
	} else {
		dname = talloc_strdup(ctx, *orig_path);
		dname[ptr1] = '\0';
		name = *orig_path;
		*adbl_path = talloc_asprintf(ctx, "%s/%s/%s", 
		  dname, APPLEDOUBLE, &name[ptr1 + 1]);
	}
#if 0
	DEBUG(3, ("ATALK: DEBUG:\n%s\n%s\n", *orig_path, *adbl_path)); 
#endif
	sys_lstat(*adbl_path, adbl_info, false);
	return 0;
}

static int atalk_unlink_file(const char *path)
{
	int ret = 0;

	become_root();
	ret = unlink(path);
	unbecome_root();
	
	return ret;
}

static void atalk_add_to_list(name_compare_entry **list)
{
	int i, count = 0;
	name_compare_entry *new_list = 0;
	name_compare_entry *cur_list = 0;

	cur_list = *list;

	if (cur_list) {
		for (i = 0, count = 0; cur_list[i].name; i ++, count ++) {
			if (strstr_m(cur_list[i].name, APPLEDOUBLE))
				return;
		}
	}

	if (!(new_list = SMB_CALLOC_ARRAY(name_compare_entry, count + 2)))
		return;

	for (i = 0; i < count; i ++) {
		new_list[i].name    = SMB_STRDUP(cur_list[i].name);
		new_list[i].is_wild = cur_list[i].is_wild;
	}

	new_list[i].name    = SMB_STRDUP(APPLEDOUBLE);
	new_list[i].is_wild = False;

	free_namearray(*list);

	*list = new_list;
	new_list = 0;
	cur_list = 0;
}

static void atalk_rrmdir(TALLOC_CTX *ctx, char *path)
{
	char *dpath;
	struct dirent *dent = 0;
	DIR *dir;

	if (!path) return;

	dir = opendir(path);
	if (!dir) return;

	while (NULL != (dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		if (!(dpath = talloc_asprintf(ctx, "%s/%s", 
					      path, dent->d_name)))
			continue;
		atalk_unlink_file(dpath);
	}

	closedir(dir);
}

/* Disk operations */

/* Directory operations */

static DIR *atalk_opendir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *mask,
			uint32_t attr)
{
	DIR *ret = 0;

	ret = SMB_VFS_NEXT_OPENDIR(handle, smb_fname, mask, attr);

	/*
	 * when we try to perform delete operation upon file which has fork
	 * in ./.AppleDouble and this directory wasn't hidden by Samba,
	 * MS Windows explorer causes the error: "Cannot find the specified file"
	 * There is some workaround to avoid this situation, i.e. if
	 * connection has not .AppleDouble entry in either veto or hide 
	 * list then it would be nice to add one.
	 */

	atalk_add_to_list(&handle->conn->hide_list);
	atalk_add_to_list(&handle->conn->veto_list);

	return ret;
}

static DIR *atalk_fdopendir(struct vfs_handle_struct *handle, files_struct *fsp, const char *mask, uint32_t attr)
{
	DIR *ret = 0;

	ret = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);

	if (ret == NULL) {
		return ret;
	}

	/*
	 * when we try to perform delete operation upon file which has fork
	 * in ./.AppleDouble and this directory wasn't hidden by Samba,
	 * MS Windows explorer causes the error: "Cannot find the specified file"
	 * There is some workaround to avoid this situation, i.e. if
	 * connection has not .AppleDouble entry in either veto or hide 
	 * list then it would be nice to add one.
	 */

	atalk_add_to_list(&handle->conn->hide_list);
	atalk_add_to_list(&handle->conn->veto_list);

	return ret;
}

static int atalk_rmdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	bool add = False;
	TALLOC_CTX *ctx = 0;
	const char *path = smb_fname->base_name;
	char *dpath;

	if (!handle->conn->cwd || !path) goto exit_rmdir;

	/* due to there is no way to change bDeleteVetoFiles variable
	 * from this module, gotta use talloc stuff..
	 */

	strstr_m(path, APPLEDOUBLE) ? (add = False) : (add = True);

	if (!(ctx = talloc_init("remove_directory")))
		goto exit_rmdir;

	if (!(dpath = talloc_asprintf(ctx, "%s/%s%s", 
	  handle->conn->cwd, path, add ? "/"APPLEDOUBLE : "")))
		goto exit_rmdir;

	atalk_rrmdir(ctx, dpath);

exit_rmdir:
	talloc_destroy(ctx);
	return SMB_VFS_NEXT_RMDIR(handle, smb_fname);
}

/* File operations */

static int atalk_rename(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_src,
			const struct smb_filename *smb_fname_dst)
{
	int ret = 0;
	char *oldname = NULL;
	char *adbl_path = NULL;
	char *orig_path = NULL;
	SMB_STRUCT_STAT adbl_info;
	SMB_STRUCT_STAT orig_info;
	NTSTATUS status;

	ret = SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);

	status = get_full_smb_filename(talloc_tos(), smb_fname_src, &oldname);
	if (!NT_STATUS_IS_OK(status)) {
		return ret;
	}

	if (atalk_build_paths(talloc_tos(), handle->conn->cwd, oldname,
			      &adbl_path, &orig_path, &adbl_info,
			      &orig_info) != 0)
		goto exit_rename;

	if (S_ISDIR(orig_info.st_ex_mode) || S_ISREG(orig_info.st_ex_mode)) {
		DEBUG(3, ("ATALK: %s has passed..\n", adbl_path));		
		goto exit_rename;
	}

	atalk_unlink_file(adbl_path);

exit_rename:
	TALLOC_FREE(oldname);
	TALLOC_FREE(adbl_path);
	TALLOC_FREE(orig_path);
	return ret;
}

static int atalk_unlink(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int ret = 0, i;
	char *path = NULL;
	char *adbl_path = NULL;
	char *orig_path = NULL;
	SMB_STRUCT_STAT adbl_info;
	SMB_STRUCT_STAT orig_info;
	NTSTATUS status;

	ret = SMB_VFS_NEXT_UNLINK(handle, smb_fname);

	status = get_full_smb_filename(talloc_tos(), smb_fname, &path);
	if (!NT_STATUS_IS_OK(status)) {
		return ret;
	}

	/* no .AppleDouble sync if veto or hide list is empty,
	 * otherwise "Cannot find the specified file" error will be caused
	 */

	if (!handle->conn->veto_list) return ret;
	if (!handle->conn->hide_list) return ret;

	for (i = 0; handle->conn->veto_list[i].name; i ++) {
		if (strstr_m(handle->conn->veto_list[i].name, APPLEDOUBLE))
			break;
	}

	if (!handle->conn->veto_list[i].name) {
		for (i = 0; handle->conn->hide_list[i].name; i ++) {
			if (strstr_m(handle->conn->hide_list[i].name, APPLEDOUBLE))
				break;
			else {
				DEBUG(3, ("ATALK: %s is not hidden, skipped..\n",
				  APPLEDOUBLE));		
				goto exit_unlink;
			}
		}
	}

	if (atalk_build_paths(talloc_tos(), handle->conn->cwd, path,
			      &adbl_path, &orig_path,
			      &adbl_info, &orig_info) != 0)
		goto exit_unlink;

	if (S_ISDIR(orig_info.st_ex_mode) || S_ISREG(orig_info.st_ex_mode)) {
		DEBUG(3, ("ATALK: %s has passed..\n", adbl_path));
		goto exit_unlink;
	}

	atalk_unlink_file(adbl_path);

exit_unlink:
	TALLOC_FREE(path);
	TALLOC_FREE(adbl_path);
	TALLOC_FREE(orig_path);
	return ret;
}

static int atalk_chmod(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int ret = 0;
	int ret1 = 0;
	char *adbl_path = 0;
	char *orig_path = 0;
	SMB_STRUCT_STAT adbl_info;
	SMB_STRUCT_STAT orig_info;
	TALLOC_CTX *ctx;

	ret = SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);

	if (!(ctx = talloc_init("chmod_file")))
		return ret;

	ret1 = atalk_build_paths(ctx,
			handle->conn->cwd,
			smb_fname->base_name,
			&adbl_path,
			&orig_path,
			&adbl_info,
			&orig_info);
	if (ret1 != 0) {
		goto exit_chmod;
	}

	if (!S_ISDIR(orig_info.st_ex_mode) && !S_ISREG(orig_info.st_ex_mode)) {
		DEBUG(3, ("ATALK: %s has passed..\n", orig_path));		
		goto exit_chmod;
	}

	chmod(adbl_path, ADOUBLEMODE);

exit_chmod:	
	talloc_destroy(ctx);
	return ret;
}

static int atalk_chown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int ret = 0;
	char *adbl_path = 0;
	char *orig_path = 0;
	SMB_STRUCT_STAT adbl_info;
	SMB_STRUCT_STAT orig_info;
	TALLOC_CTX *ctx;

	ret = SMB_VFS_NEXT_CHOWN(handle, smb_fname, uid, gid);

	if (!(ctx = talloc_init("chown_file")))
		return ret;

	if (atalk_build_paths(ctx, handle->conn->cwd, smb_fname->base_name,
			      &adbl_path, &orig_path,
			      &adbl_info, &orig_info) != 0)
		goto exit_chown;

	if (!S_ISDIR(orig_info.st_ex_mode) && !S_ISREG(orig_info.st_ex_mode)) {
		DEBUG(3, ("ATALK: %s has passed..\n", orig_path));		
		goto exit_chown;
	}

	if (chown(adbl_path, uid, gid) == -1) {
		DEBUG(3, ("ATALK: chown error %s\n", strerror(errno)));
	}

exit_chown:	
	talloc_destroy(ctx);
	return ret;
}

static int atalk_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int ret = 0;
	char *adbl_path = 0;
	char *orig_path = 0;
	SMB_STRUCT_STAT adbl_info;
	SMB_STRUCT_STAT orig_info;
	TALLOC_CTX *ctx;

	ret = SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);

	if (!(ctx = talloc_init("lchown_file")))
		return ret;

	if (atalk_build_paths(ctx, handle->conn->cwd, smb_fname->base_name,
			      &adbl_path, &orig_path,
			      &adbl_info, &orig_info) != 0)
		goto exit_lchown;

	if (!S_ISDIR(orig_info.st_ex_mode) && !S_ISREG(orig_info.st_ex_mode)) {
		DEBUG(3, ("ATALK: %s has passed..\n", orig_path));		
		goto exit_lchown;
	}

	if (lchown(adbl_path, uid, gid) == -1) {
		DEBUG(3, ("ATALK: lchown error %s\n", strerror(errno)));
	}

exit_lchown:	
	talloc_destroy(ctx);
	return ret;
}

static struct vfs_fn_pointers vfs_netatalk_fns = {
	.opendir_fn = atalk_opendir,
	.fdopendir_fn = atalk_fdopendir,
	.rmdir_fn = atalk_rmdir,
	.rename_fn = atalk_rename,
	.unlink_fn = atalk_unlink,
	.chmod_fn = atalk_chmod,
	.chown_fn = atalk_chown,
	.lchown_fn = atalk_lchown,
};

NTSTATUS vfs_netatalk_init(void);
NTSTATUS vfs_netatalk_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "netatalk",
				&vfs_netatalk_fns);
}
