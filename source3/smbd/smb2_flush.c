/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../lib/util/tevent_ntstatus.h"

static struct tevent_req *smbd_smb2_flush_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbd_smb2_request *smb2req,
					       struct files_struct *fsp);
static NTSTATUS smbd_smb2_flush_recv(struct tevent_req *req);

static void smbd_smb2_request_flush_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_flush(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	const uint8_t *inbody;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x18);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_file_id_persistent	= BVAL(inbody, 0x08);
	in_file_id_volatile	= BVAL(inbody, 0x10);

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_flush_send(req, req->sconn->ev_ctx,
				      req, in_fsp);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_flush_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_flush_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_flush_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	outbody = smbd_smb2_generate_outbody(req, 0x04);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

struct smbd_smb2_flush_state {
	struct smbd_smb2_request *smb2req;
};

static void smbd_smb2_flush_done(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_flush_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbd_smb2_request *smb2req,
					       struct files_struct *fsp)
{
	struct tevent_req *req;
	struct tevent_req *subreq;
	struct smbd_smb2_flush_state *state;
	struct smb_request *smbreq;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_flush_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;

	DEBUG(10,("smbd_smb2_flush: %s - %s\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

	smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (IS_IPC(smbreq->conn)) {
		tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
		return tevent_req_post(req, ev);
	}

	if (!CHECK_WRITE(fsp)) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return tevent_req_post(req, ev);
	}

	if (fsp->fh->fd == -1) {
		tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
		return tevent_req_post(req, ev);
	}

	if (!lp_strict_sync(SNUM(smbreq->conn))) {
		/*
		 * No strict sync. Don't really do
		 * anything here.
		 */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	ret = flush_write_cache(fsp, SAMBA_SYNC_FLUSH);
	if (ret == -1) {
		tevent_req_nterror(req,  map_nt_error_from_unix(errno));
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_FSYNC_SEND(state, ev, fsp);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, smbd_smb2_flush_done, req);

	/* Ensure any close request knows about this outstanding IO. */
	if (!aio_add_req_to_fsp(fsp, req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}

	increment_outstanding_aio_calls();
	return req;

}

static void smbd_smb2_flush_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	struct vfs_aio_state vfs_aio_state;

	decrement_outstanding_aio_calls();

	ret = SMB_VFS_FSYNC_RECV(subreq, &vfs_aio_state);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, vfs_aio_state.error);
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_flush_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}
