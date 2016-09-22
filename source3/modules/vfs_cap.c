/*
 * CAP VFS module for Samba 3.x Version 0.3
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002-2003
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) TAKAHASHI Motonobu (monyo), 2003
 * Copyright (C) Jeremy Allison, 2007
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

/* cap functions */
static char *capencode(TALLOC_CTX *ctx, const char *from);
static char *capdecode(TALLOC_CTX *ctx, const char *from);

static uint64_t cap_disk_free(vfs_handle_struct *handle, const char *path,
			      uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return (uint64_t)-1;
	}
	return SMB_VFS_NEXT_DISK_FREE(handle, cappath, bsize, dfree, dsize);
}

static int cap_get_quota(vfs_handle_struct *handle, const char *path,
			 enum SMB_QUOTA_TYPE qtype, unid_t id,
			 SMB_DISK_QUOTA *dq)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_GET_QUOTA(handle, cappath, qtype, id, dq);
}

static DIR *cap_opendir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *mask,
			uint32_t attr)
{
	char *capname = capencode(talloc_tos(), smb_fname->base_name);
	struct smb_filename *cap_smb_fname = NULL;

	if (!capname) {
		errno = ENOMEM;
		return NULL;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					capname,
					NULL,
					NULL,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(capname);
		errno = ENOMEM;
		return NULL;
	}
	return SMB_VFS_NEXT_OPENDIR(handle, cap_smb_fname, mask, attr);
}

static struct dirent *cap_readdir(vfs_handle_struct *handle,
				      DIR *dirp,
				      SMB_STRUCT_STAT *sbuf)
{
	struct dirent *result;
	struct dirent *newdirent;
	char *newname;
	size_t newnamelen;
	DEBUG(3,("cap: cap_readdir\n"));

	result = SMB_VFS_NEXT_READDIR(handle, dirp, NULL);
	if (!result) {
		return NULL;
	}

	newname = capdecode(talloc_tos(), result->d_name);
	if (!newname) {
		return NULL;
	}
	DEBUG(3,("cap: cap_readdir: %s\n", newname));
	newnamelen = strlen(newname)+1;
	newdirent = talloc_size(
		talloc_tos(), sizeof(struct dirent) + newnamelen);
	if (!newdirent) {
		return NULL;
	}
	talloc_set_name_const(newdirent, "struct dirent");
	memcpy(newdirent, result, sizeof(struct dirent));
	memcpy(&newdirent->d_name, newname, newnamelen);
	return newdirent;
}

static int cap_mkdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	struct smb_filename *cap_smb_fname = NULL;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	return SMB_VFS_NEXT_MKDIR(handle, cap_smb_fname, mode);
}

static int cap_rmdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname)
{
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	struct smb_filename *cap_smb_fname = NULL;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	return SMB_VFS_NEXT_RMDIR(handle, cap_smb_fname);
}

static int cap_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
		    files_struct *fsp, int flags, mode_t mode)
{
	char *cappath;
	char *tmp_base_name = NULL;
	int ret;

	cappath = capencode(talloc_tos(), smb_fname->base_name);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = cappath;

	DEBUG(3,("cap: cap_open for %s\n", smb_fname_str_dbg(smb_fname)));
	ret = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(cappath);

	return ret;
}

static int cap_rename(vfs_handle_struct *handle,
		      const struct smb_filename *smb_fname_src,
		      const struct smb_filename *smb_fname_dst)
{
	char *capold = NULL;
	char *capnew = NULL;
	struct smb_filename *smb_fname_src_tmp = NULL;
	struct smb_filename *smb_fname_dst_tmp = NULL;
	int ret = -1;

	capold = capencode(talloc_tos(), smb_fname_src->base_name);
	capnew = capencode(talloc_tos(), smb_fname_dst->base_name);
	if (!capold || !capnew) {
		errno = ENOMEM;
		goto out;
	}

	/* Setup temporary smb_filename structs. */
	smb_fname_src_tmp = cp_smb_filename(talloc_tos(), smb_fname_src);
	if (smb_fname_src_tmp == NULL) {
		errno = ENOMEM;
		goto out;
	}
	smb_fname_dst_tmp = cp_smb_filename(talloc_tos(), smb_fname_dst);
	if (smb_fname_dst_tmp == NULL) {
		errno = ENOMEM;
		goto out;
	}

	smb_fname_src_tmp->base_name = capold;
	smb_fname_dst_tmp->base_name = capnew;

	ret = SMB_VFS_NEXT_RENAME(handle, smb_fname_src_tmp,
				  smb_fname_dst_tmp);
 out:
	TALLOC_FREE(capold);
	TALLOC_FREE(capnew);
	TALLOC_FREE(smb_fname_src_tmp);
	TALLOC_FREE(smb_fname_dst_tmp);

	return ret;
}

static int cap_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	char *cappath;
	char *tmp_base_name = NULL;
	int ret;

	cappath = capencode(talloc_tos(), smb_fname->base_name);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = cappath;

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(cappath);

	return ret;
}

static int cap_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	char *cappath;
	char *tmp_base_name = NULL;
	int ret;

	cappath = capencode(talloc_tos(), smb_fname->base_name);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = cappath;

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(cappath);

	return ret;
}

static int cap_unlink(vfs_handle_struct *handle,
		      const struct smb_filename *smb_fname)
{
	struct smb_filename *smb_fname_tmp = NULL;
	char *cappath = NULL;
	int ret;

	cappath = capencode(talloc_tos(), smb_fname->base_name);
	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	/* Setup temporary smb_filename structs. */
	smb_fname_tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	smb_fname_tmp->base_name = cappath;

	ret = SMB_VFS_NEXT_UNLINK(handle, smb_fname_tmp);

	TALLOC_FREE(smb_fname_tmp);
	return ret;
}

static int cap_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	int ret;
	int saved_errno;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_CHMOD(handle, cap_smb_fname, mode);
	saved_errno = errno;
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	errno = saved_errno;
	return ret;
}

static int cap_chown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	int ret;
	int saved_errno;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_CHOWN(handle, cap_smb_fname, uid, gid);
	saved_errno = errno;
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	errno = saved_errno;
	return ret;
}

static int cap_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	int ret;
	int saved_errno;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_LCHOWN(handle, cap_smb_fname, uid, gid);
	saved_errno = errno;
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	errno = saved_errno;
	return ret;
}

static int cap_chdir(vfs_handle_struct *handle, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	DEBUG(3,("cap: cap_chdir for %s\n", path));
	return SMB_VFS_NEXT_CHDIR(handle, cappath);
}

static int cap_ntimes(vfs_handle_struct *handle,
		      const struct smb_filename *smb_fname,
		      struct smb_file_time *ft)
{
	struct smb_filename *smb_fname_tmp = NULL;
	char *cappath = NULL;
	int ret;

	cappath = capencode(talloc_tos(), smb_fname->base_name);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	/* Setup temporary smb_filename structs. */
	smb_fname_tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	smb_fname_tmp->base_name = cappath;

	ret = SMB_VFS_NEXT_NTIMES(handle, smb_fname_tmp, ft);

	TALLOC_FREE(smb_fname_tmp);
	return ret;
}


static int cap_symlink(vfs_handle_struct *handle, const char *oldpath,
		       const char *newpath)
{
	char *capold = capencode(talloc_tos(), oldpath);
	char *capnew = capencode(talloc_tos(), newpath);

	if (!capold || !capnew) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_SYMLINK(handle, capold, capnew);
}

static int cap_readlink(vfs_handle_struct *handle, const char *path,
			char *buf, size_t bufsiz)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_READLINK(handle, cappath, buf, bufsiz);
}

static int cap_link(vfs_handle_struct *handle, const char *oldpath, const char *newpath)
{
	char *capold = capencode(talloc_tos(), oldpath);
	char *capnew = capencode(talloc_tos(), newpath);

	if (!capold || !capnew) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_LINK(handle, capold, capnew);
}

static int cap_mknod(vfs_handle_struct *handle, const char *path, mode_t mode, SMB_DEV_T dev)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_MKNOD(handle, cappath, mode, dev);
}

static char *cap_realpath(vfs_handle_struct *handle, const char *path)
{
        /* monyo need capencode'ed and capdecode'ed? */
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return NULL;
	}
	return SMB_VFS_NEXT_REALPATH(handle, cappath);
}

static int cap_chmod_acl(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	int ret;
	int saved_errno;

	/* If the underlying VFS doesn't have ACL support... */
	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_CHMOD_ACL(handle, cap_smb_fname, mode);
	saved_errno = errno;
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	errno = saved_errno;
	return ret;
}

static SMB_ACL_T cap_sys_acl_get_file(vfs_handle_struct *handle,
				      const char *path, SMB_ACL_TYPE_T type,
				      TALLOC_CTX *mem_ctx)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return (SMB_ACL_T)NULL;
	}
	return SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, cappath, type, mem_ctx);
}

static int cap_sys_acl_set_file(vfs_handle_struct *handle, const char *path, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, cappath, acltype, theacl);
}

static int cap_sys_acl_delete_def_file(vfs_handle_struct *handle, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, cappath);
}

static ssize_t cap_getxattr(vfs_handle_struct *handle, const char *path, const char *name, void *value, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_GETXATTR(handle, cappath, capname, value, size);
}

static ssize_t cap_fgetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path, void *value, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FGETXATTR(handle, fsp, cappath, value, size);
}

static ssize_t cap_listxattr(vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_LISTXATTR(handle, cappath, list, size);
}

static int cap_removexattr(vfs_handle_struct *handle, const char *path, const char *name)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_REMOVEXATTR(handle, cappath, capname);
}

static int cap_fremovexattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, cappath);
}

static int cap_setxattr(vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	char *cappath = capencode(talloc_tos(), path);
	char *capname = capencode(talloc_tos(), name);

	if (!cappath || !capname) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_SETXATTR(handle, cappath, capname, value, size, flags);
}

static int cap_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path, const void *value, size_t size, int flags)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FSETXATTR(handle, fsp, cappath, value, size, flags);
}

static struct vfs_fn_pointers vfs_cap_fns = {
	.disk_free_fn = cap_disk_free,
	.get_quota_fn = cap_get_quota,
	.opendir_fn = cap_opendir,
	.readdir_fn = cap_readdir,
	.mkdir_fn = cap_mkdir,
	.rmdir_fn = cap_rmdir,
	.open_fn = cap_open,
	.rename_fn = cap_rename,
	.stat_fn = cap_stat,
	.lstat_fn = cap_lstat,
	.unlink_fn = cap_unlink,
	.chmod_fn = cap_chmod,
	.chown_fn = cap_chown,
	.lchown_fn = cap_lchown,
	.chdir_fn = cap_chdir,
	.ntimes_fn = cap_ntimes,
	.symlink_fn = cap_symlink,
	.readlink_fn = cap_readlink,
	.link_fn = cap_link,
	.mknod_fn = cap_mknod,
	.realpath_fn = cap_realpath,
	.chmod_acl_fn = cap_chmod_acl,
	.sys_acl_get_file_fn = cap_sys_acl_get_file,
	.sys_acl_set_file_fn = cap_sys_acl_set_file,
	.sys_acl_delete_def_file_fn = cap_sys_acl_delete_def_file,
	.getxattr_fn = cap_getxattr,
	.fgetxattr_fn = cap_fgetxattr,
	.listxattr_fn = cap_listxattr,
	.removexattr_fn = cap_removexattr,
	.fremovexattr_fn = cap_fremovexattr,
	.setxattr_fn = cap_setxattr,
	.fsetxattr_fn = cap_fsetxattr
};

NTSTATUS vfs_cap_init(void);
NTSTATUS vfs_cap_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "cap",
				&vfs_cap_fns);
}

/* For CAP functions */
#define hex_tag ':'
#define hex2bin(c)		hex2bin_table[(unsigned char)(c)]
#define bin2hex(c)		bin2hex_table[(unsigned char)(c)]
#define is_hex(s)		((s)[0] == hex_tag)

static unsigned char hex2bin_table[256] = {
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x20 */
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, /* 0x30 */
0000, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0000, /* 0x40 */
0000, 0000, 0000, 0000, 0000, 0000, 0000, 0000,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x50 */
0000, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0000, /* 0x60 */
0000, 0000, 0000, 0000, 0000, 0000, 0000, 0000,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x70 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x80 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x90 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xa0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xb0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xc0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xd0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xe0 */
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  /* 0xf0 */
};
static unsigned char bin2hex_table[256] = "0123456789abcdef";

/*******************************************************************
  original code -> ":xx"  - CAP format
********************************************************************/

static char *capencode(TALLOC_CTX *ctx, const char *from)
{
	char *out = NULL;
	const char *p1;
	char *to = NULL;
	size_t len = 0;

	for (p1 = from; *p1; p1++) {
		if ((unsigned char)*p1 >= 0x80) {
			len += 3;
		} else {
			len++;
		}
	}
	len++;

	to = talloc_array(ctx, char, len);
	if (!to) {
		return NULL;
	}

	for (out = to; *from;) {
		/* buffer husoku error */
		if ((unsigned char)*from >= 0x80) {
			*out++ = hex_tag;
			*out++ = bin2hex (((*from)>>4)&0x0f);
			*out++ = bin2hex ((*from)&0x0f);
			from++;
		} else {
			*out++ = *from++;
		}
  	}
	*out = '\0';
	return to;
}

/*******************************************************************
  CAP -> original code
********************************************************************/
/* ":xx" -> a byte */

static char *capdecode(TALLOC_CTX *ctx, const char *from)
{
	const char *p1;
	char *out = NULL;
	char *to = NULL;
	size_t len = 0;

	for (p1 = from; *p1; len++) {
		if (is_hex(p1)) {
			p1 += 3;
		} else {
			p1++;
		}
	}
	len++;

	to = talloc_array(ctx, char, len);
	if (!to) {
		return NULL;
	}

	for (out = to; *from;) {
		if (is_hex(from)) {
			*out++ = (hex2bin(from[1])<<4) | (hex2bin(from[2]));
			from += 3;
		} else {
			*out++ = *from++;
		}
	}
	*out = '\0';
	return to;
}
