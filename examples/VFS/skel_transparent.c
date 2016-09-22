/* 
 * Skeleton VFS module.  Implements passthrough operation of all VFS
 * calls to disk functions.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) Jeremy Allison 2009
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

#include "../source3/include/includes.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"

/* PLEASE,PLEASE READ THE VFS MODULES CHAPTER OF THE 
   SAMBA DEVELOPERS GUIDE!!!!!!
 */

/* If you take this file as template for your module
 * please make sure that you remove all skel_XXX() functions you don't
 * want to implement!! The passthrough operations are not
 * neccessary in a real module.
 *
 * --metze
 */

static int skel_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void skel_disconnect(vfs_handle_struct *handle)
{
	SMB_VFS_NEXT_DISCONNECT(handle);
}

static uint64_t skel_disk_free(vfs_handle_struct *handle, const char *path,
			       uint64_t *bsize,
			       uint64_t *dfree, uint64_t *dsize)
{
	return SMB_VFS_NEXT_DISK_FREE(handle, path, bsize, dfree, dsize);
}

static int skel_get_quota(vfs_handle_struct *handle, const char *path,
			  enum SMB_QUOTA_TYPE qtype, unid_t id,
			  SMB_DISK_QUOTA *dq)
{
	return SMB_VFS_NEXT_GET_QUOTA(handle, path, qtype, id, dq);
}

static int skel_set_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
			  unid_t id, SMB_DISK_QUOTA *dq)
{
	return SMB_VFS_NEXT_SET_QUOTA(handle, qtype, id, dq);
}

static int skel_get_shadow_copy_data(vfs_handle_struct *handle,
				     files_struct *fsp,
				     struct shadow_copy_data *shadow_copy_data,
				     bool labels)
{
	return SMB_VFS_NEXT_GET_SHADOW_COPY_DATA(handle, fsp, shadow_copy_data,
						 labels);
}

static int skel_statvfs(struct vfs_handle_struct *handle, const char *path,
			struct vfs_statvfs_struct *statbuf)
{
	return SMB_VFS_NEXT_STATVFS(handle, path, statbuf);
}

static uint32_t skel_fs_capabilities(struct vfs_handle_struct *handle,
				     enum timestamp_set_resolution *p_ts_res)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);
}

static NTSTATUS skel_get_dfs_referrals(struct vfs_handle_struct *handle,
				       struct dfs_GetDFSReferral *r)
{
	return SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r);
}

static DIR *skel_opendir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *mask,
			uint32_t attr)
{
	return SMB_VFS_NEXT_OPENDIR(handle, smb_fname, mask, attr);
}

static NTSTATUS skel_snap_check_path(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     const char *service_path,
				     char **base_volume)
{
	return SMB_VFS_NEXT_SNAP_CHECK_PATH(handle, mem_ctx, service_path,
					    base_volume);
}

static NTSTATUS skel_snap_create(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 const char *base_volume,
				 time_t *tstamp,
				 bool rw,
				 char **base_path,
				 char **snap_path)
{
	return SMB_VFS_NEXT_SNAP_CREATE(handle, mem_ctx, base_volume, tstamp,
					rw, base_path, snap_path);
}

static NTSTATUS skel_snap_delete(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 char *base_path,
				 char *snap_path)
{
	return SMB_VFS_NEXT_SNAP_DELETE(handle, mem_ctx, base_path, snap_path);
}

static DIR *skel_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
			   const char *mask, uint32_t attr)
{
	return SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
}

static struct dirent *skel_readdir(vfs_handle_struct *handle,
				   DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);
}

static void skel_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
	SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset);
}

static long skel_telldir(vfs_handle_struct *handle, DIR *dirp)
{
	return SMB_VFS_NEXT_TELLDIR(handle, dirp);
}

static void skel_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	SMB_VFS_NEXT_REWINDDIR(handle, dirp);
}

static int skel_mkdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	return SMB_VFS_NEXT_MKDIR(handle, smb_fname, mode);
}

static int skel_rmdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_RMDIR(handle, smb_fname);
}

static int skel_closedir(vfs_handle_struct *handle, DIR *dir)
{
	return SMB_VFS_NEXT_CLOSEDIR(handle, dir);
}

static void skel_init_search_op(struct vfs_handle_struct *handle, DIR *dirp)
{
	SMB_VFS_NEXT_INIT_SEARCH_OP(handle, dirp);
}

static int skel_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
		     files_struct *fsp, int flags, mode_t mode)
{
	return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
}

static NTSTATUS skel_create_file(struct vfs_handle_struct *handle,
				 struct smb_request *req,
				 uint16_t root_dir_fid,
				 struct smb_filename *smb_fname,
				 uint32_t access_mask,
				 uint32_t share_access,
				 uint32_t create_disposition,
				 uint32_t create_options,
				 uint32_t file_attributes,
				 uint32_t oplock_request,
				 struct smb2_lease *lease,
				 uint64_t allocation_size,
				 uint32_t private_flags,
				 struct security_descriptor *sd,
				 struct ea_list *ea_list,
				 files_struct ** result, int *pinfo,
				 const struct smb2_create_blobs *in_context_blobs,
				 struct smb2_create_blobs *out_context_blobs)
{
	return SMB_VFS_NEXT_CREATE_FILE(handle,
					req,
					root_dir_fid,
					smb_fname,
					access_mask,
					share_access,
					create_disposition,
					create_options,
					file_attributes,
					oplock_request,
					lease,
					allocation_size,
					private_flags,
					sd, ea_list, result, pinfo,
					in_context_blobs, out_context_blobs);
}

static int skel_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	return SMB_VFS_NEXT_CLOSE(handle, fsp);
}

static ssize_t skel_vfs_read(vfs_handle_struct *handle, files_struct *fsp,
			     void *data, size_t n)
{
	return SMB_VFS_NEXT_READ(handle, fsp, data, n);
}

static ssize_t skel_pread(vfs_handle_struct *handle, files_struct *fsp,
			  void *data, size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
}

struct skel_pread_state {
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void skel_pread_done(struct tevent_req *subreq);

static struct tevent_req *skel_pread_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp,
					  void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct skel_pread_state *state;

	req = tevent_req_create(mem_ctx, &state, struct skel_pread_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_pread_done, req);
	return req;
}

static void skel_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
	    tevent_req_callback_data(subreq, struct tevent_req);
	struct skel_pread_state *state =
	    tevent_req_data(req, struct skel_pread_state);

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t skel_pread_recv(struct tevent_req *req,
			       struct vfs_aio_state *vfs_aio_state)
{
	struct skel_pread_state *state =
	    tevent_req_data(req, struct skel_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static ssize_t skel_write(vfs_handle_struct *handle, files_struct *fsp,
			  const void *data, size_t n)
{
	return SMB_VFS_NEXT_WRITE(handle, fsp, data, n);
}

static ssize_t skel_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			   const void *data, size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
}

struct skel_pwrite_state {
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void skel_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *skel_pwrite_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   const void *data,
					   size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct skel_pwrite_state *state;

	req = tevent_req_create(mem_ctx, &state, struct skel_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
					  n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_pwrite_done, req);
	return req;
}

static void skel_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
	    tevent_req_callback_data(subreq, struct tevent_req);
	struct skel_pwrite_state *state =
	    tevent_req_data(req, struct skel_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t skel_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct skel_pwrite_state *state =
	    tevent_req_data(req, struct skel_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static off_t skel_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence)
{
	return SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);
}

static ssize_t skel_sendfile(vfs_handle_struct *handle, int tofd,
			     files_struct *fromfsp, const DATA_BLOB *hdr,
			     off_t offset, size_t n)
{
	return SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, hdr, offset, n);
}

static ssize_t skel_recvfile(vfs_handle_struct *handle, int fromfd,
			     files_struct *tofsp, off_t offset, size_t n)
{
	return SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, n);
}

static int skel_rename(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname_src,
		       const struct smb_filename *smb_fname_dst)
{
	return SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);
}

static int skel_fsync(vfs_handle_struct *handle, files_struct *fsp)
{
	return SMB_VFS_NEXT_FSYNC(handle, fsp);
}

struct skel_fsync_state {
	int ret;
	struct vfs_aio_state vfs_aio_state;
};

static void skel_fsync_done(struct tevent_req *subreq);

static struct tevent_req *skel_fsync_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct skel_fsync_state *state;

	req = tevent_req_create(mem_ctx, &state, struct skel_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = SMB_VFS_NEXT_FSYNC_SEND(state, ev, handle, fsp);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_fsync_done, req);
	return req;
}

static void skel_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
	    tevent_req_callback_data(subreq, struct tevent_req);
	struct skel_fsync_state *state =
	    tevent_req_data(req, struct skel_fsync_state);

	state->ret = SMB_VFS_FSYNC_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static int skel_fsync_recv(struct tevent_req *req,
			   struct vfs_aio_state *vfs_aio_state)
{
	struct skel_fsync_state *state =
	    tevent_req_data(req, struct skel_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int skel_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_STAT(handle, smb_fname);
}

static int skel_fstat(vfs_handle_struct *handle, files_struct *fsp,
		      SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
}

static int skel_lstat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
}

static uint64_t skel_get_alloc_size(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_GET_ALLOC_SIZE(handle, fsp, sbuf);
}

static int skel_unlink(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
}

static int skel_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	return SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
}

static int skel_fchmod(vfs_handle_struct *handle, files_struct *fsp,
		       mode_t mode)
{
	return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
}

static int skel_chown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	return SMB_VFS_NEXT_CHOWN(handle, smb_fname, uid, gid);
}

static int skel_fchown(vfs_handle_struct *handle, files_struct *fsp,
		       uid_t uid, gid_t gid)
{
	return SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
}

static int skel_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	return SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
}

static int skel_chdir(vfs_handle_struct *handle, const char *path)
{
	return SMB_VFS_NEXT_CHDIR(handle, path);
}

static char *skel_getwd(vfs_handle_struct *handle)
{
	return SMB_VFS_NEXT_GETWD(handle);
}

static int skel_ntimes(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       struct smb_file_time *ft)
{
	return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

static int skel_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
			  off_t offset)
{
	return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
}

static int skel_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			  uint32_t mode, off_t offset, off_t len)
{
	return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
}

static bool skel_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
		      off_t offset, off_t count, int type)
{
	return SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);
}

static int skel_kernel_flock(struct vfs_handle_struct *handle,
			     struct files_struct *fsp, uint32_t share_mode,
			     uint32_t access_mask)
{
	return SMB_VFS_NEXT_KERNEL_FLOCK(handle, fsp, share_mode, access_mask);
}

static int skel_linux_setlease(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, int leasetype)
{
	return SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);
}

static bool skel_getlock(vfs_handle_struct *handle, files_struct *fsp,
			 off_t *poffset, off_t *pcount, int *ptype,
			 pid_t *ppid)
{
	return SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype, ppid);
}

static int skel_symlink(vfs_handle_struct *handle, const char *oldpath,
			const char *newpath)
{
	return SMB_VFS_NEXT_SYMLINK(handle, oldpath, newpath);
}

static int skel_vfs_readlink(vfs_handle_struct *handle, const char *path,
			     char *buf, size_t bufsiz)
{
	return SMB_VFS_NEXT_READLINK(handle, path, buf, bufsiz);
}

static int skel_link(vfs_handle_struct *handle, const char *oldpath,
		     const char *newpath)
{
	return SMB_VFS_NEXT_LINK(handle, oldpath, newpath);
}

static int skel_mknod(vfs_handle_struct *handle, const char *path, mode_t mode,
		      SMB_DEV_T dev)
{
	return SMB_VFS_NEXT_MKNOD(handle, path, mode, dev);
}

static char *skel_realpath(vfs_handle_struct *handle, const char *path)
{
	return SMB_VFS_NEXT_REALPATH(handle, path);
}

static int skel_chflags(vfs_handle_struct *handle, const char *path,
			uint flags)
{
	return SMB_VFS_NEXT_CHFLAGS(handle, path, flags);
}

static struct file_id skel_file_id_create(vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf);
}

struct skel_cc_state {
	struct vfs_handle_struct *handle;
	off_t copied;
};
static void skel_copy_chunk_done(struct tevent_req *subreq);

static struct tevent_req *skel_copy_chunk_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct files_struct *src_fsp,
					       off_t src_off,
					       struct files_struct *dest_fsp,
					       off_t dest_off,
					       off_t num)
{
	struct tevent_req *req;
	struct tevent_req *subreq;
	struct skel_cc_state *cc_state;

	req = tevent_req_create(mem_ctx, &cc_state, struct skel_cc_state);
	if (req == NULL) {
		return NULL;
	}

	cc_state->handle = handle;
	subreq = SMB_VFS_NEXT_COPY_CHUNK_SEND(handle, cc_state, ev,
					      src_fsp, src_off,
					      dest_fsp, dest_off, num);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, skel_copy_chunk_done, req);
	return req;
}

static void skel_copy_chunk_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct skel_cc_state *cc_state
			= tevent_req_data(req, struct skel_cc_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_COPY_CHUNK_RECV(cc_state->handle,
					      subreq,
					      &cc_state->copied);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS skel_copy_chunk_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied)
{
	struct skel_cc_state *cc_state
			= tevent_req_data(req, struct skel_cc_state);
	NTSTATUS status;

	*copied = cc_state->copied;
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS skel_get_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     struct smb_filename *smb_fname,
				     uint16_t *_compression_fmt)
{
	return SMB_VFS_NEXT_GET_COMPRESSION(handle, mem_ctx, fsp, smb_fname,
					    _compression_fmt);
}

static NTSTATUS skel_set_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     uint16_t compression_fmt)
{
	return SMB_VFS_NEXT_SET_COMPRESSION(handle, mem_ctx, fsp,
					    compression_fmt);
}

static NTSTATUS skel_streaminfo(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				unsigned int *num_streams,
				struct stream_struct **streams)
{
	return SMB_VFS_NEXT_STREAMINFO(handle,
				fsp,
				smb_fname,
				mem_ctx,
				num_streams,
				streams);
}

static int skel_get_real_filename(struct vfs_handle_struct *handle,
				  const char *path,
				  const char *name,
				  TALLOC_CTX *mem_ctx, char **found_name)
{
	return SMB_VFS_NEXT_GET_REAL_FILENAME(handle,
					      path, name, mem_ctx, found_name);
}

static const char *skel_connectpath(struct vfs_handle_struct *handle,
				    const char *filename)
{
	return SMB_VFS_NEXT_CONNECTPATH(handle, filename);
}

static NTSTATUS skel_brl_lock_windows(struct vfs_handle_struct *handle,
				      struct byte_range_lock *br_lck,
				      struct lock_struct *plock,
				      bool blocking_lock)
{
	return SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle,
					     br_lck, plock, blocking_lock);
}

static bool skel_brl_unlock_windows(struct vfs_handle_struct *handle,
				    struct messaging_context *msg_ctx,
				    struct byte_range_lock *br_lck,
				    const struct lock_struct *plock)
{
	return SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, msg_ctx, br_lck, plock);
}

static bool skel_brl_cancel_windows(struct vfs_handle_struct *handle,
				    struct byte_range_lock *br_lck,
				    struct lock_struct *plock)
{
	return SMB_VFS_NEXT_BRL_CANCEL_WINDOWS(handle, br_lck, plock);
}

static bool skel_strict_lock(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     struct lock_struct *plock)
{
	return SMB_VFS_NEXT_STRICT_LOCK(handle, fsp, plock);
}

static void skel_strict_unlock(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       struct lock_struct *plock)
{
	SMB_VFS_NEXT_STRICT_UNLOCK(handle, fsp, plock);
}

static NTSTATUS skel_translate_name(struct vfs_handle_struct *handle,
				    const char *mapped_name,
				    enum vfs_translate_direction direction,
				    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
	return SMB_VFS_NEXT_TRANSLATE_NAME(handle, mapped_name, direction,
					   mem_ctx, pmapped_name);
}

static NTSTATUS skel_fsctl(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   TALLOC_CTX *ctx,
			   uint32_t function,
			   uint16_t req_flags,	/* Needed for UNICODE ... */
			   const uint8_t *_in_data,
			   uint32_t in_len,
			   uint8_t ** _out_data,
			   uint32_t max_out_len, uint32_t *out_len)
{
	return SMB_VFS_NEXT_FSCTL(handle,
				  fsp,
				  ctx,
				  function,
				  req_flags,
				  _in_data,
				  in_len, _out_data, max_out_len, out_len);
}

static NTSTATUS skel_readdir_attr(struct vfs_handle_struct *handle,
				  const struct smb_filename *fname,
				  TALLOC_CTX *mem_ctx,
				  struct readdir_attr_data **pattr_data)
{
	return SMB_VFS_NEXT_READDIR_ATTR(handle, fname, mem_ctx, pattr_data);
}

static NTSTATUS skel_get_dos_attributes(struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				uint32_t *dosmode)
{
	return SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);
}

static NTSTATUS skel_fget_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t *dosmode)
{
	return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);
}

static NTSTATUS skel_set_dos_attributes(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t dosmode)
{
	return SMB_VFS_NEXT_SET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);
}

static NTSTATUS skel_fset_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t dosmode)
{
	return SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);
}

static NTSTATUS skel_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
	return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx,
					ppdesc);
}

static NTSTATUS skel_get_nt_acl(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	return SMB_VFS_NEXT_GET_NT_ACL(handle,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
}

static NTSTATUS skel_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info_sent,
				 const struct security_descriptor *psd)
{
	return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
}

static int skel_chmod_acl(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	return SMB_VFS_NEXT_CHMOD_ACL(handle, smb_fname, mode);
}

static int skel_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp,
			   mode_t mode)
{
	return SMB_VFS_NEXT_FCHMOD_ACL(handle, fsp, mode);
}

static SMB_ACL_T skel_sys_acl_get_file(vfs_handle_struct *handle,
				       const char *path_p,
				       SMB_ACL_TYPE_T type,
				       TALLOC_CTX *mem_ctx)
{
	return SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, path_p, type, mem_ctx);
}

static SMB_ACL_T skel_sys_acl_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp, TALLOC_CTX *mem_ctx)
{
	return SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx);
}

static int skel_sys_acl_blob_get_file(vfs_handle_struct *handle,
				      const char *path_p, TALLOC_CTX *mem_ctx,
				      char **blob_description, DATA_BLOB *blob)
{
	return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, path_p, mem_ctx,
						  blob_description, blob);
}

static int skel_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				    files_struct *fsp, TALLOC_CTX *mem_ctx,
				    char **blob_description, DATA_BLOB *blob)
{
	return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx,
						blob_description, blob);
}

static int skel_sys_acl_set_file(vfs_handle_struct *handle, const char *name,
				 SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, name, acltype, theacl);
}

static int skel_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_ACL_T theacl)
{
	return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);
}

static int skel_sys_acl_delete_def_file(vfs_handle_struct *handle,
					const char *path)
{
	return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, path);
}

static ssize_t skel_getxattr(vfs_handle_struct *handle, const char *path,
			     const char *name, void *value, size_t size)
{
	return SMB_VFS_NEXT_GETXATTR(handle, path, name, value, size);
}

static ssize_t skel_fgetxattr(vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name,
			      void *value, size_t size)
{
	return SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
}

static ssize_t skel_listxattr(vfs_handle_struct *handle, const char *path,
			      char *list, size_t size)
{
	return SMB_VFS_NEXT_LISTXATTR(handle, path, list, size);
}

static ssize_t skel_flistxattr(vfs_handle_struct *handle,
			       struct files_struct *fsp, char *list,
			       size_t size)
{
	return SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);
}

static int skel_removexattr(vfs_handle_struct *handle, const char *path,
			    const char *name)
{
	return SMB_VFS_NEXT_REMOVEXATTR(handle, path, name);
}

static int skel_fremovexattr(vfs_handle_struct *handle,
			     struct files_struct *fsp, const char *name)
{
	return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int skel_setxattr(vfs_handle_struct *handle, const char *path,
			 const char *name, const void *value, size_t size,
			 int flags)
{
	return SMB_VFS_NEXT_SETXATTR(handle, path, name, value, size, flags);
}

static int skel_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	return SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);
}

static bool skel_aio_force(struct vfs_handle_struct *handle,
			   struct files_struct *fsp)
{
	return SMB_VFS_NEXT_AIO_FORCE(handle, fsp);
}

static bool skel_is_offline(struct vfs_handle_struct *handle,
			    const struct smb_filename *fname,
			    SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_IS_OFFLINE(handle, fname, sbuf);
}

static int skel_set_offline(struct vfs_handle_struct *handle,
			    const struct smb_filename *fname)
{
	return SMB_VFS_NEXT_SET_OFFLINE(handle, fname);
}

/* VFS operations structure */

struct vfs_fn_pointers skel_transparent_fns = {
	/* Disk operations */

	.connect_fn = skel_connect,
	.disconnect_fn = skel_disconnect,
	.disk_free_fn = skel_disk_free,
	.get_quota_fn = skel_get_quota,
	.set_quota_fn = skel_set_quota,
	.get_shadow_copy_data_fn = skel_get_shadow_copy_data,
	.statvfs_fn = skel_statvfs,
	.fs_capabilities_fn = skel_fs_capabilities,
	.get_dfs_referrals_fn = skel_get_dfs_referrals,
	.snap_check_path_fn = skel_snap_check_path,
	.snap_create_fn = skel_snap_create,
	.snap_delete_fn = skel_snap_delete,

	/* Directory operations */

	.opendir_fn = skel_opendir,
	.fdopendir_fn = skel_fdopendir,
	.readdir_fn = skel_readdir,
	.seekdir_fn = skel_seekdir,
	.telldir_fn = skel_telldir,
	.rewind_dir_fn = skel_rewind_dir,
	.mkdir_fn = skel_mkdir,
	.rmdir_fn = skel_rmdir,
	.closedir_fn = skel_closedir,
	.init_search_op_fn = skel_init_search_op,

	/* File operations */

	.open_fn = skel_open,
	.create_file_fn = skel_create_file,
	.close_fn = skel_close_fn,
	.read_fn = skel_vfs_read,
	.pread_fn = skel_pread,
	.pread_send_fn = skel_pread_send,
	.pread_recv_fn = skel_pread_recv,
	.write_fn = skel_write,
	.pwrite_fn = skel_pwrite,
	.pwrite_send_fn = skel_pwrite_send,
	.pwrite_recv_fn = skel_pwrite_recv,
	.lseek_fn = skel_lseek,
	.sendfile_fn = skel_sendfile,
	.recvfile_fn = skel_recvfile,
	.rename_fn = skel_rename,
	.fsync_fn = skel_fsync,
	.fsync_send_fn = skel_fsync_send,
	.fsync_recv_fn = skel_fsync_recv,
	.stat_fn = skel_stat,
	.fstat_fn = skel_fstat,
	.lstat_fn = skel_lstat,
	.get_alloc_size_fn = skel_get_alloc_size,
	.unlink_fn = skel_unlink,
	.chmod_fn = skel_chmod,
	.fchmod_fn = skel_fchmod,
	.chown_fn = skel_chown,
	.fchown_fn = skel_fchown,
	.lchown_fn = skel_lchown,
	.chdir_fn = skel_chdir,
	.getwd_fn = skel_getwd,
	.ntimes_fn = skel_ntimes,
	.ftruncate_fn = skel_ftruncate,
	.fallocate_fn = skel_fallocate,
	.lock_fn = skel_lock,
	.kernel_flock_fn = skel_kernel_flock,
	.linux_setlease_fn = skel_linux_setlease,
	.getlock_fn = skel_getlock,
	.symlink_fn = skel_symlink,
	.readlink_fn = skel_vfs_readlink,
	.link_fn = skel_link,
	.mknod_fn = skel_mknod,
	.realpath_fn = skel_realpath,
	.chflags_fn = skel_chflags,
	.file_id_create_fn = skel_file_id_create,
	.copy_chunk_send_fn = skel_copy_chunk_send,
	.copy_chunk_recv_fn = skel_copy_chunk_recv,
	.get_compression_fn = skel_get_compression,
	.set_compression_fn = skel_set_compression,

	.streaminfo_fn = skel_streaminfo,
	.get_real_filename_fn = skel_get_real_filename,
	.connectpath_fn = skel_connectpath,
	.brl_lock_windows_fn = skel_brl_lock_windows,
	.brl_unlock_windows_fn = skel_brl_unlock_windows,
	.brl_cancel_windows_fn = skel_brl_cancel_windows,
	.strict_lock_fn = skel_strict_lock,
	.strict_unlock_fn = skel_strict_unlock,
	.translate_name_fn = skel_translate_name,
	.fsctl_fn = skel_fsctl,
	.readdir_attr_fn = skel_readdir_attr,

	/* DOS attributes. */
	.get_dos_attributes_fn = skel_get_dos_attributes,
	.fget_dos_attributes_fn = skel_fget_dos_attributes,
	.set_dos_attributes_fn = skel_set_dos_attributes,
	.fset_dos_attributes_fn = skel_fset_dos_attributes,

	/* NT ACL operations. */

	.fget_nt_acl_fn = skel_fget_nt_acl,
	.get_nt_acl_fn = skel_get_nt_acl,
	.fset_nt_acl_fn = skel_fset_nt_acl,

	/* POSIX ACL operations. */

	.chmod_acl_fn = skel_chmod_acl,
	.fchmod_acl_fn = skel_fchmod_acl,

	.sys_acl_get_file_fn = skel_sys_acl_get_file,
	.sys_acl_get_fd_fn = skel_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = skel_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = skel_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = skel_sys_acl_set_file,
	.sys_acl_set_fd_fn = skel_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = skel_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = skel_getxattr,
	.fgetxattr_fn = skel_fgetxattr,
	.listxattr_fn = skel_listxattr,
	.flistxattr_fn = skel_flistxattr,
	.removexattr_fn = skel_removexattr,
	.fremovexattr_fn = skel_fremovexattr,
	.setxattr_fn = skel_setxattr,
	.fsetxattr_fn = skel_fsetxattr,

	/* aio operations */
	.aio_force_fn = skel_aio_force,

	/* offline operations */
	.is_offline_fn = skel_is_offline,
	.set_offline_fn = skel_set_offline
};

static_decl_vfs;
NTSTATUS vfs_skel_transparent_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "skel_transparent",
				&skel_transparent_fns);
}
