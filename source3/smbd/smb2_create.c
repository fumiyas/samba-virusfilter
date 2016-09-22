/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "printing.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../librpc/gen_ndr/ndr_smb2_lease_struct.h"
#include "../lib/util/tevent_ntstatus.h"
#include "messages.h"

int map_smb2_oplock_levels_to_samba(uint8_t in_oplock_level)
{
	switch(in_oplock_level) {
	case SMB2_OPLOCK_LEVEL_NONE:
		return NO_OPLOCK;
	case SMB2_OPLOCK_LEVEL_II:
		return LEVEL_II_OPLOCK;
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		return EXCLUSIVE_OPLOCK;
	case SMB2_OPLOCK_LEVEL_BATCH:
		return BATCH_OPLOCK;
	case SMB2_OPLOCK_LEVEL_LEASE:
		return LEASE_OPLOCK;
	default:
		DEBUG(2,("map_smb2_oplock_levels_to_samba: "
			"unknown level %u\n",
			(unsigned int)in_oplock_level));
		return NO_OPLOCK;
	}
}

static uint8_t map_samba_oplock_levels_to_smb2(int oplock_type)
{
	if (BATCH_OPLOCK_TYPE(oplock_type)) {
		return SMB2_OPLOCK_LEVEL_BATCH;
	} else if (EXCLUSIVE_OPLOCK_TYPE(oplock_type)) {
		return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	} else if (oplock_type == LEVEL_II_OPLOCK) {
		return SMB2_OPLOCK_LEVEL_II;
	} else if (oplock_type == LEASE_OPLOCK) {
		return SMB2_OPLOCK_LEVEL_LEASE;
	} else {
		return SMB2_OPLOCK_LEVEL_NONE;
	}
}

static struct tevent_req *smbd_smb2_create_send(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct smbd_smb2_request *smb2req,
			uint8_t in_oplock_level,
			uint32_t in_impersonation_level,
			uint32_t in_desired_access,
			uint32_t in_file_attributes,
			uint32_t in_share_access,
			uint32_t in_create_disposition,
			uint32_t in_create_options,
			const char *in_name,
			struct smb2_create_blobs in_context_blobs);
static NTSTATUS smbd_smb2_create_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			uint8_t *out_oplock_level,
			uint32_t *out_create_action,
			struct timespec *out_creation_ts,
			struct timespec *out_last_access_ts,
			struct timespec *out_last_write_ts,
			struct timespec *out_change_ts,
			uint64_t *out_allocation_size,
			uint64_t *out_end_of_file,
			uint32_t *out_file_attributes,
			uint64_t *out_file_id_persistent,
			uint64_t *out_file_id_volatile,
			struct smb2_create_blobs *out_context_blobs);

static void smbd_smb2_request_create_done(struct tevent_req *tsubreq);
NTSTATUS smbd_smb2_request_process_create(struct smbd_smb2_request *smb2req)
{
	const uint8_t *inbody;
	const struct iovec *indyniov;
	uint8_t in_oplock_level;
	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	uint32_t in_create_disposition;
	uint32_t in_create_options;
	uint16_t in_name_offset;
	uint16_t in_name_length;
	DATA_BLOB in_name_buffer;
	char *in_name_string;
	size_t in_name_string_size;
	uint32_t name_offset = 0;
	uint32_t name_available_length = 0;
	uint32_t in_context_offset;
	uint32_t in_context_length;
	DATA_BLOB in_context_buffer;
	struct smb2_create_blobs in_context_blobs;
	uint32_t context_offset = 0;
	uint32_t context_available_length = 0;
	uint32_t dyn_offset;
	NTSTATUS status;
	bool ok;
	struct tevent_req *tsubreq;

	status = smbd_smb2_request_verify_sizes(smb2req, 0x39);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(smb2req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(smb2req);

	in_oplock_level		= CVAL(inbody, 0x03);
	in_impersonation_level	= IVAL(inbody, 0x04);
	in_desired_access	= IVAL(inbody, 0x18);
	in_file_attributes	= IVAL(inbody, 0x1C);
	in_share_access		= IVAL(inbody, 0x20);
	in_create_disposition	= IVAL(inbody, 0x24);
	in_create_options	= IVAL(inbody, 0x28);
	in_name_offset		= SVAL(inbody, 0x2C);
	in_name_length		= SVAL(inbody, 0x2E);
	in_context_offset	= IVAL(inbody, 0x30);
	in_context_length	= IVAL(inbody, 0x34);

	/*
	 * First check if the dynamic name and context buffers
	 * are correctly specified.
	 *
	 * Note: That we don't check if the name and context buffers
	 *       overlap
	 */

	dyn_offset = SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(smb2req);

	if (in_name_offset == 0 && in_name_length == 0) {
		/* This is ok */
		name_offset = 0;
	} else if (in_name_offset < dyn_offset) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	} else {
		name_offset = in_name_offset - dyn_offset;
	}

	indyniov = SMBD_SMB2_IN_DYN_IOV(smb2req);

	if (name_offset > indyniov->iov_len) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	name_available_length = indyniov->iov_len - name_offset;

	if (in_name_length > name_available_length) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_name_buffer.data = (uint8_t *)indyniov->iov_base + name_offset;
	in_name_buffer.length = in_name_length;

	if (in_context_offset == 0 && in_context_length == 0) {
		/* This is ok */
		context_offset = 0;
	} else if (in_context_offset < dyn_offset) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	} else {
		context_offset = in_context_offset - dyn_offset;
	}

	if (context_offset > indyniov->iov_len) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	context_available_length = indyniov->iov_len - context_offset;

	if (in_context_length > context_available_length) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_context_buffer.data = (uint8_t *)indyniov->iov_base +
		context_offset;
	in_context_buffer.length = in_context_length;

	/*
	 * Now interpret the name and context buffers
	 */

	ok = convert_string_talloc(smb2req, CH_UTF16, CH_UNIX,
				   in_name_buffer.data,
				   in_name_buffer.length,
				   &in_name_string,
				   &in_name_string_size);
	if (!ok) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_ILLEGAL_CHARACTER);
	}

	if (in_name_buffer.length == 0) {
		in_name_string_size = 0;
	}

	if (strlen(in_name_string) != in_name_string_size) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_OBJECT_NAME_INVALID);
	}

	ZERO_STRUCT(in_context_blobs);
	status = smb2_create_blob_parse(smb2req, in_context_buffer, &in_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(smb2req, status);
	}

	tsubreq = smbd_smb2_create_send(smb2req,
				       smb2req->sconn->ev_ctx,
				       smb2req,
				       in_oplock_level,
				       in_impersonation_level,
				       in_desired_access,
				       in_file_attributes,
				       in_share_access,
				       in_create_disposition,
				       in_create_options,
				       in_name_string,
				       in_context_blobs);
	if (tsubreq == NULL) {
		smb2req->subreq = NULL;
		return smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(tsubreq, smbd_smb2_request_create_done, smb2req);

	return smbd_smb2_request_pending_queue(smb2req, tsubreq, 500);
}

static uint64_t get_mid_from_smb2req(struct smbd_smb2_request *smb2req)
{
	uint8_t *reqhdr = SMBD_SMB2_OUT_HDR_PTR(smb2req);
	return BVAL(reqhdr, SMB2_HDR_MESSAGE_ID);
}

static void smbd_smb2_request_create_done(struct tevent_req *tsubreq)
{
	struct smbd_smb2_request *smb2req = tevent_req_callback_data(tsubreq,
					struct smbd_smb2_request);
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint8_t out_oplock_level = 0;
	uint32_t out_create_action = 0;
	connection_struct *conn = smb2req->tcon->compat;
	struct timespec out_creation_ts = { 0, };
	struct timespec out_last_access_ts = { 0, };
	struct timespec out_last_write_ts = { 0, };
	struct timespec out_change_ts = { 0, };
	uint64_t out_allocation_size = 0;
	uint64_t out_end_of_file = 0;
	uint32_t out_file_attributes = 0;
	uint64_t out_file_id_persistent = 0;
	uint64_t out_file_id_volatile = 0;
	struct smb2_create_blobs out_context_blobs;
	DATA_BLOB out_context_buffer;
	uint16_t out_context_buffer_offset = 0;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_create_recv(tsubreq,
				       smb2req,
				       &out_oplock_level,
				       &out_create_action,
				       &out_creation_ts,
				       &out_last_access_ts,
				       &out_last_write_ts,
				       &out_change_ts,
				       &out_allocation_size,
				       &out_end_of_file,
				       &out_file_attributes,
				       &out_file_id_persistent,
				       &out_file_id_volatile,
				       &out_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(smb2req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	status = smb2_create_blob_push(smb2req, &out_context_buffer, out_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(smb2req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	if (out_context_buffer.length > 0) {
		out_context_buffer_offset = SMB2_HDR_BODY + 0x58;
	}

	outbody = smbd_smb2_generate_outbody(smb2req, 0x58);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x58 + 1);	/* struct size */
	SCVAL(outbody.data, 0x02,
	      out_oplock_level);		/* oplock level */
	SCVAL(outbody.data, 0x03, 0);		/* reserved */
	SIVAL(outbody.data, 0x04,
	      out_create_action);		/* create action */
	put_long_date_timespec(conn->ts_res,
	      (char *)outbody.data + 0x08,
	      out_creation_ts);			/* creation time */
	put_long_date_timespec(conn->ts_res,
	      (char *)outbody.data + 0x10,
	      out_last_access_ts);		/* last access time */
	put_long_date_timespec(conn->ts_res,
	      (char *)outbody.data + 0x18,
	      out_last_write_ts);		/* last write time */
	put_long_date_timespec(conn->ts_res,
	      (char *)outbody.data + 0x20,
	      out_change_ts);			/* change time */
	SBVAL(outbody.data, 0x28,
	      out_allocation_size);		/* allocation size */
	SBVAL(outbody.data, 0x30,
	      out_end_of_file);			/* end of file */
	SIVAL(outbody.data, 0x38,
	      out_file_attributes);		/* file attributes */
	SIVAL(outbody.data, 0x3C, 0);		/* reserved */
	SBVAL(outbody.data, 0x40,
	      out_file_id_persistent);		/* file id (persistent) */
	SBVAL(outbody.data, 0x48,
	      out_file_id_volatile);		/* file id (volatile) */
	SIVAL(outbody.data, 0x50,
	      out_context_buffer_offset);	/* create contexts offset */
	SIVAL(outbody.data, 0x54,
	      out_context_buffer.length);	/* create contexts length */

	outdyn = out_context_buffer;

	error = smbd_smb2_request_done(smb2req, outbody, &outdyn);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(smb2req->xconn,
						 nt_errstr(error));
		return;
	}
}

static bool smb2_lease_key_valid(const struct smb2_lease_key *key)
{
	return ((key->data[0] != 0) || (key->data[1] != 0));
}

static NTSTATUS smbd_smb2_create_durable_lease_check(
	const char *requested_filename, const struct files_struct *fsp,
	const struct smb2_lease *lease_ptr)
{
	struct smb_filename *smb_fname = NULL;
	uint32_t ucf_flags = UCF_PREP_CREATEFILE;
	NTSTATUS status;

	if (lease_ptr == NULL) {
		if (fsp->oplock_type != LEASE_OPLOCK) {
			return NT_STATUS_OK;
		}
		DEBUG(10, ("Reopened file has lease, but no lease "
			   "requested\n"));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (fsp->oplock_type != LEASE_OPLOCK) {
		DEBUG(10, ("Lease requested, but reopened file has no "
			   "lease\n"));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!smb2_lease_key_equal(&lease_ptr->lease_key,
				  &fsp->lease->lease.lease_key)) {
		DEBUG(10, ("Different lease key requested than found "
			   "in reopened file\n"));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	status = filename_convert(talloc_tos(), fsp->conn, false,
				  requested_filename, ucf_flags,
				  NULL, &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("filename_convert returned %s\n",
			   nt_errstr(status)));
		return status;
	}

	if (!strequal(fsp->fsp_name->base_name, smb_fname->base_name)) {
		DEBUG(10, ("Lease requested for file %s, reopened file "
			   "is named %s\n", smb_fname->base_name,
			   fsp->fsp_name->base_name));
		TALLOC_FREE(smb_fname);
		return NT_STATUS_INVALID_PARAMETER;
	}

	TALLOC_FREE(smb_fname);

	return NT_STATUS_OK;
}

struct smbd_smb2_create_state {
	struct smbd_smb2_request *smb2req;
	struct smb_request *smb1req;
	bool open_was_deferred;
	struct tevent_timer *te;
	struct tevent_immediate *im;
	struct timeval request_time;
	struct file_id id;
	struct deferred_open_record *open_rec;
	uint8_t out_oplock_level;
	uint32_t out_create_action;
	struct timespec out_creation_ts;
	struct timespec out_last_access_ts;
	struct timespec out_last_write_ts;
	struct timespec out_change_ts;
	uint64_t out_allocation_size;
	uint64_t out_end_of_file;
	uint32_t out_file_attributes;
	uint64_t out_file_id_persistent;
	uint64_t out_file_id_volatile;
	struct smb2_create_blobs *out_context_blobs;
};

static struct tevent_req *smbd_smb2_create_send(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct smbd_smb2_request *smb2req,
			uint8_t in_oplock_level,
			uint32_t in_impersonation_level,
			uint32_t in_desired_access,
			uint32_t in_file_attributes,
			uint32_t in_share_access,
			uint32_t in_create_disposition,
			uint32_t in_create_options,
			const char *in_name,
			struct smb2_create_blobs in_context_blobs)
{
	struct tevent_req *req = NULL;
	struct smbd_smb2_create_state *state = NULL;
	NTSTATUS status;
	struct smb_request *smb1req = NULL;
	files_struct *result = NULL;
	int info;
	int requested_oplock_level;
	struct smb2_create_blob *dhnc = NULL;
	struct smb2_create_blob *dh2c = NULL;
	struct smb2_create_blob *dhnq = NULL;
	struct smb2_create_blob *dh2q = NULL;
	struct smb2_create_blob *rqls = NULL;
	bool replay_operation = false;

	if(lp_fake_oplocks(SNUM(smb2req->tcon->compat))) {
		requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	} else {
		requested_oplock_level = in_oplock_level;
	}


	if (smb2req->subreq == NULL) {
		/* New create call. */
		req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_create_state);
		if (req == NULL) {
			return NULL;
		}
		state->smb2req = smb2req;

		smb1req = smbd_smb2_fake_smb_request(smb2req);
		if (tevent_req_nomem(smb1req, req)) {
			return tevent_req_post(req, ev);
		}
		state->smb1req = smb1req;
		smb2req->subreq = req;
		DEBUG(10,("smbd_smb2_create: name[%s]\n",
			in_name));
	} else {
		/* Re-entrant create call. */
		req = smb2req->subreq;
		state = tevent_req_data(req,
				struct smbd_smb2_create_state);
		smb1req = state->smb1req;
		TALLOC_FREE(state->out_context_blobs);
		DEBUG(10,("smbd_smb2_create_send: reentrant for file %s\n",
			in_name ));
	}

	state->out_context_blobs = talloc_zero(state, struct smb2_create_blobs);
	if (tevent_req_nomem(state->out_context_blobs, req)) {
		return tevent_req_post(req, ev);
	}

	dhnq = smb2_create_blob_find(&in_context_blobs,
				     SMB2_CREATE_TAG_DHNQ);
	dhnc = smb2_create_blob_find(&in_context_blobs,
				     SMB2_CREATE_TAG_DHNC);
	dh2q = smb2_create_blob_find(&in_context_blobs,
				     SMB2_CREATE_TAG_DH2Q);
	dh2c = smb2_create_blob_find(&in_context_blobs,
				     SMB2_CREATE_TAG_DH2C);
	if (smb2req->xconn->smb2.server.capabilities & SMB2_CAP_LEASING) {
		rqls = smb2_create_blob_find(&in_context_blobs,
					     SMB2_CREATE_TAG_RQLS);
	}

	if ((dhnc && dh2c) || (dhnc && dh2q) || (dh2c && dhnq) ||
	    (dh2q && dh2c))
	{
		/* not both are allowed at the same time */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	if (dhnc) {
		uint32_t num_blobs_allowed;

		if (dhnc->data.length != 16) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		/*
		 * According to MS-SMB2: 3.3.5.9.7, "Handling the
		 * SMB2_CREATE_DURABLE_HANDLE_RECONNECT Create Context",
		 * we should ignore an additional dhnq blob, but fail
		 * the request (with status OBJECT_NAME_NOT_FOUND) if
		 * any other extra create blob has been provided.
		 *
		 * (Note that the cases of an additional dh2q or dh2c blob
		 *  which require a different error code, have been treated
		 *  above.)
		 */

		if (dhnq) {
			num_blobs_allowed = 2;
		} else {
			num_blobs_allowed = 1;
		}

		if (rqls != NULL) {
			num_blobs_allowed += 1;
		}

		if (in_context_blobs.num_blobs != num_blobs_allowed) {
			tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return tevent_req_post(req, ev);
		}
	}

	if (dh2c) {
		uint32_t num_blobs_allowed;

		if (dh2c->data.length != 36) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		/*
		 * According to MS-SMB2: 3.3.5.9.12, "Handling the
		 * SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 Create Context",
		 * we should fail the request with status
		 * OBJECT_NAME_NOT_FOUND if any other create blob has been
		 * provided.
		 *
		 * (Note that the cases of an additional dhnq, dhnc or dh2q
		 *  blob which require a different error code, have been
		 *  treated above.)
		 */

		num_blobs_allowed = 1;

		if (rqls != NULL) {
			num_blobs_allowed += 1;
		}

		if (in_context_blobs.num_blobs != num_blobs_allowed) {
			tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return tevent_req_post(req, ev);
		}
	}

	if (IS_IPC(smb1req->conn)) {
		const char *pipe_name = in_name;

		if (dhnc || dh2c) {
			/* durable handles are not supported on IPC$ */
			tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return tevent_req_post(req, ev);
		}

		if (!lp_nt_pipe_support()) {
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		status = open_np_file(smb1req, pipe_name, &result);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
		info = FILE_WAS_OPENED;
	} else if (CAN_PRINT(smb1req->conn)) {
		if (dhnc || dh2c) {
			/* durable handles are not supported on printers */
			tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return tevent_req_post(req, ev);
		}

		status = file_new(smb1req, smb1req->conn, &result);
		if(!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}

		status = print_spool_open(result, in_name,
					  smb1req->vuid);
		if (!NT_STATUS_IS_OK(status)) {
			file_free(smb1req, result);
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
		info = FILE_WAS_CREATED;
	} else {
		char *fname;
		struct smb2_create_blob *exta = NULL;
		struct ea_list *ea_list = NULL;
		struct smb2_create_blob *mxac = NULL;
		NTTIME max_access_time = 0;
		struct smb2_create_blob *secd = NULL;
		struct security_descriptor *sec_desc = NULL;
		struct smb2_create_blob *alsi = NULL;
		uint64_t allocation_size = 0;
		struct smb2_create_blob *twrp = NULL;
		struct smb2_create_blob *qfid = NULL;
		struct GUID _create_guid = GUID_zero();
		struct GUID *create_guid = NULL;
		bool update_open = false;
		bool durable_requested = false;
		uint32_t durable_timeout_msec = 0;
		bool do_durable_reconnect = false;
		uint64_t persistent_id = 0;
		struct smb2_lease lease;
		struct smb2_lease *lease_ptr = NULL;
		ssize_t lease_len = -1;
		bool need_replay_cache = false;
		struct smbXsrv_open *op = NULL;
#if 0
		struct smb2_create_blob *svhdx = NULL;
#endif

		exta = smb2_create_blob_find(&in_context_blobs,
					     SMB2_CREATE_TAG_EXTA);
		mxac = smb2_create_blob_find(&in_context_blobs,
					     SMB2_CREATE_TAG_MXAC);
		secd = smb2_create_blob_find(&in_context_blobs,
					     SMB2_CREATE_TAG_SECD);
		alsi = smb2_create_blob_find(&in_context_blobs,
					     SMB2_CREATE_TAG_ALSI);
		twrp = smb2_create_blob_find(&in_context_blobs,
					     SMB2_CREATE_TAG_TWRP);
		qfid = smb2_create_blob_find(&in_context_blobs,
					     SMB2_CREATE_TAG_QFID);
#if 0
		if (smb2req->xconn->protocol >= PROTOCOL_SMB3_02) {
			/*
			 * This was introduced with SMB3_02
			 */
			svhdx = smb2_create_blob_find(&in_context_blobs,
						      SVHDX_OPEN_DEVICE_CONTEXT);
		}
#endif

		fname = talloc_strdup(state, in_name);
		if (tevent_req_nomem(fname, req)) {
			return tevent_req_post(req, ev);
		}

		if (exta) {
			if (!lp_ea_support(SNUM(smb2req->tcon->compat))) {
				tevent_req_nterror(req,
					NT_STATUS_EAS_NOT_SUPPORTED);
				return tevent_req_post(req, ev);
			}

			ea_list = read_nttrans_ea_list(mem_ctx,
				(const char *)exta->data.data, exta->data.length);
			if (!ea_list) {
				DEBUG(10,("smbd_smb2_create_send: read_ea_name_list failed.\n"));
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			/*
			 * NB. When SMB2+ unix extensions are added,
			 * we need to relax this check in invalid
			 * names - we used to not do this if
			 * lp_posix_pathnames() was false.
			 */
			if (ea_list_has_invalid_name(ea_list)) {
				tevent_req_nterror(req, STATUS_INVALID_EA_NAME);
				return tevent_req_post(req, ev);
			}
		}

		if (mxac) {
			if (mxac->data.length == 0) {
				max_access_time = 0;
			} else if (mxac->data.length == 8) {
				max_access_time = BVAL(mxac->data.data, 0);
			} else {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}
		}

		if (secd) {
			enum ndr_err_code ndr_err;

			sec_desc = talloc_zero(state, struct security_descriptor);
			if (tevent_req_nomem(sec_desc, req)) {
				return tevent_req_post(req, ev);
			}

			ndr_err = ndr_pull_struct_blob(&secd->data,
				sec_desc, sec_desc,
				(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				DEBUG(2,("ndr_pull_security_descriptor failed: %s\n",
					 ndr_errstr(ndr_err)));
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}
		}

		if (dhnq) {
			if (dhnq->data.length != 16) {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			if (dh2q) {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			/*
			 * durable handle request is processed below.
			 */
			durable_requested = true;
			/*
			 * Set the timeout to 16 mins.
			 *
			 * TODO: test this against Windows 2012
			 *       as the default for durable v2 is 1 min.
			 */
			durable_timeout_msec = (16*60*1000);
		}

		if (dh2q) {
			const uint8_t *p = dh2q->data.data;
			uint32_t durable_v2_timeout = 0;
			DATA_BLOB create_guid_blob;
			const uint8_t *hdr;
			uint32_t flags;

			if (dh2q->data.length != 32) {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			if (dhnq) {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			durable_v2_timeout = IVAL(p, 0);
			create_guid_blob = data_blob_const(p + 16, 16);

			status = GUID_from_ndr_blob(&create_guid_blob,
						    &_create_guid);
			if (tevent_req_nterror(req, status)) {
				return tevent_req_post(req, ev);
			}
			create_guid = &_create_guid;
			/*
			 * we need to store the create_guid later
			 */
			update_open = true;

			/*
			 * And we need to create a cache for replaying the
			 * create.
			 */
			need_replay_cache = true;

			/*
			 * durable handle v2 request processed below
			 */
			durable_requested = true;
			durable_timeout_msec = durable_v2_timeout;
			if (durable_timeout_msec == 0) {
				/*
				 * Set the timeout to 1 min as default.
				 *
				 * This matches Windows 2012.
				 */
				durable_timeout_msec = (60*1000);
			}

			/*
			 * Check for replay operation.
			 * Only consider it when we have dh2q.
			 * If we do not have a replay operation, verify that
			 * the create_guid is not cached for replay.
			 */
			hdr = SMBD_SMB2_IN_HDR_PTR(smb2req);
			flags = IVAL(hdr, SMB2_HDR_FLAGS);
			replay_operation =
				flags & SMB2_HDR_FLAG_REPLAY_OPERATION;

			status = smb2srv_open_lookup_replay_cache(
					smb2req->xconn, create_guid,
					0 /* now */, &op);

			if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
				replay_operation = false;
			} else if (tevent_req_nterror(req, status)) {
				DBG_WARNING("smb2srv_open_lookup_replay_cache "
					    "failed: %s\n", nt_errstr(status));
				return tevent_req_post(req, ev);
			} else if (!replay_operation) {
				/*
				 * If a create without replay operation flag
				 * is sent but with a create_guid that is
				 * currently in the replay cache -- fail.
				 */
				status = NT_STATUS_DUPLICATE_OBJECTID;
				(void)tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}

		if (dhnc) {
			persistent_id = BVAL(dhnc->data.data, 0);

			do_durable_reconnect = true;
		}

		if (dh2c) {
			const uint8_t *p = dh2c->data.data;
			DATA_BLOB create_guid_blob;

			persistent_id = BVAL(p, 0);
			create_guid_blob = data_blob_const(p + 16, 16);

			status = GUID_from_ndr_blob(&create_guid_blob,
						    &_create_guid);
			if (tevent_req_nterror(req, status)) {
				return tevent_req_post(req, ev);
			}
			create_guid = &_create_guid;

			do_durable_reconnect = true;
		}

		if (alsi) {
			if (alsi->data.length != 8) {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}
			allocation_size = BVAL(alsi->data.data, 0);
		}

		if (twrp) {
			NTTIME nttime;
			time_t t;
			struct tm *tm;

			if (twrp->data.length != 8) {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			nttime = BVAL(twrp->data.data, 0);
			t = nt_time_to_unix(nttime);
			tm = gmtime(&t);

			TALLOC_FREE(fname);
			fname = talloc_asprintf(state,
					"%s\\@GMT-%04u.%02u.%02u-%02u.%02u.%02u",
					in_name,
					tm->tm_year + 1900,
					tm->tm_mon + 1,
					tm->tm_mday,
					tm->tm_hour,
					tm->tm_min,
					tm->tm_sec);
			if (tevent_req_nomem(fname, req)) {
				return tevent_req_post(req, ev);
			}
		}

		if (qfid) {
			if (qfid->data.length != 0) {
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}
		}

		if (rqls) {
			lease_len = smb2_lease_pull(
				rqls->data.data, rqls->data.length, &lease);
			if (lease_len == -1) {
				tevent_req_nterror(
					req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}
			lease_ptr = &lease;

			if (DEBUGLEVEL >= 10) {
				DEBUG(10, ("Got lease request size %d\n",
					   (int)lease_len));
				NDR_PRINT_DEBUG(smb2_lease, lease_ptr);
			}

			if (!smb2_lease_key_valid(&lease.lease_key)) {
				lease_ptr = NULL;
				requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
			}

			if ((smb2req->xconn->protocol < PROTOCOL_SMB3_00) &&
			    (lease.lease_version != 1)) {
				DEBUG(10, ("v2 lease key only for SMB3\n"));
				lease_ptr = NULL;
			}

			/*
			 * Replay with a lease is only allowed if the
			 * established open carries a lease with the
			 * same lease key.
			 */
			if (replay_operation) {
				struct smb2_lease *op_ls =
						&op->compat->lease->lease;
				int op_oplock = op->compat->oplock_type;

				if (map_samba_oplock_levels_to_smb2(op_oplock)
				    != SMB2_OPLOCK_LEVEL_LEASE)
				{
					status = NT_STATUS_ACCESS_DENIED;
					(void)tevent_req_nterror(req, status);
					return tevent_req_post(req, ev);
				}
				if (!smb2_lease_key_equal(&lease.lease_key,
							  &op_ls->lease_key))
				{
					status = NT_STATUS_ACCESS_DENIED;
					(void)tevent_req_nterror(req, status);
					return tevent_req_post(req, ev);
				}
			}
		}

		/* these are ignored for SMB2 */
		in_create_options &= ~(0x10);/* NTCREATEX_OPTIONS_SYNC_ALERT */
		in_create_options &= ~(0x20);/* NTCREATEX_OPTIONS_ASYNC_ALERT */

		in_file_attributes &= ~FILE_FLAG_POSIX_SEMANTICS;

		DEBUG(10, ("smbd_smb2_create_send: open execution phase\n"));

		/*
		 * For the backend file open procedure, there are
		 * three possible modes: replay operation (in which case
		 * there is nothing else to do), durable_reconnect or
		 * new open.
		 */
		if (replay_operation) {
			result = op->compat;
			result->op = op;
			update_open = false;
			info = op->create_action;
		} else if (do_durable_reconnect) {
			DATA_BLOB new_cookie = data_blob_null;
			NTTIME now = timeval_to_nttime(&smb2req->request_time);

			status = smb2srv_open_recreate(smb2req->xconn,
						smb1req->conn->session_info,
						persistent_id, create_guid,
						now, &op);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(3, ("smbd_smb2_create_send: "
					  "smb2srv_open_recreate failed: %s\n",
					  nt_errstr(status)));
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}

			DEBUG(10, ("smb2_create_send: %s to recreate the "
				   "smb2srv_open struct for a durable handle.\n",
				   op->global->durable ? "succeded" : "failed"));

			if (!op->global->durable) {
				talloc_free(op);
				tevent_req_nterror(req,
					NT_STATUS_OBJECT_NAME_NOT_FOUND);
				return tevent_req_post(req, ev);
			}

			status = SMB_VFS_DURABLE_RECONNECT(smb1req->conn,
						smb1req,
						op, /* smbXsrv_open input */
						op->global->backend_cookie,
						op, /* TALLOC_CTX */
						&result, &new_cookie);
			if (!NT_STATUS_IS_OK(status)) {
				NTSTATUS return_status;

				return_status = NT_STATUS_OBJECT_NAME_NOT_FOUND;

				DEBUG(3, ("smbd_smb2_create_send: "
					  "durable_reconnect failed: %s => %s\n",
					  nt_errstr(status),
					  nt_errstr(return_status)));

				tevent_req_nterror(req, return_status);
				return tevent_req_post(req, ev);
			}

			DEBUG(10, ("result->oplock_type=%u, lease_ptr==%p\n",
				   (unsigned)result->oplock_type, lease_ptr));

			status = smbd_smb2_create_durable_lease_check(
				fname, result, lease_ptr);
			if (!NT_STATUS_IS_OK(status)) {
				close_file(smb1req, result, SHUTDOWN_CLOSE);
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}

			data_blob_free(&op->global->backend_cookie);
			op->global->backend_cookie = new_cookie;

			op->status = NT_STATUS_OK;
			op->global->disconnect_time = 0;

			/* save the timout for later update */
			durable_timeout_msec = op->global->durable_timeout_msec;

			update_open = true;

			info = FILE_WAS_OPENED;
		} else {
			struct smb_filename *smb_fname = NULL;
			uint32_t ucf_flags = UCF_PREP_CREATEFILE;

			if (requested_oplock_level == SMB2_OPLOCK_LEVEL_LEASE) {
				if (lease_ptr == NULL) {
					requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
				}
			} else {
				lease_ptr = NULL;
			}

			/*
			 * For a DFS path the function parse_dfs_path()
			 * will do the path processing.
			 */

			if (!(smb1req->flags2 & FLAGS2_DFS_PATHNAMES)) {
				/* convert '\\' into '/' */
				status = check_path_syntax(fname);
				if (!NT_STATUS_IS_OK(status)) {
					tevent_req_nterror(req, status);
					return tevent_req_post(req, ev);
				}
			}

			status = filename_convert(req,
						  smb1req->conn,
						  smb1req->flags2 & FLAGS2_DFS_PATHNAMES,
						  fname,
						  ucf_flags,
						  NULL, /* ppath_contains_wcards */
						  &smb_fname);
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}

			/*
			 * MS-SMB2: 2.2.13 SMB2 CREATE Request
			 * ImpersonationLevel ... MUST contain one of the
			 * following values. The server MUST validate this
			 * field, but otherwise ignore it.
			 *
			 * NB. The source4/torture/smb2/durable_open.c test
			 * shows this check is only done on real opens, not
			 * on durable handle-reopens.
			 */

			if (in_impersonation_level >
					SMB2_IMPERSONATION_DELEGATE) {
				tevent_req_nterror(req,
					NT_STATUS_BAD_IMPERSONATION_LEVEL);
				return tevent_req_post(req, ev);
			}

			/*
			 * We know we're going to do a local open, so now
			 * we must be protocol strict. JRA.
			 *
			 * MS-SMB2: 3.3.5.9 - Receiving an SMB2 CREATE Request
			 * If the file name length is greater than zero and the
			 * first character is a path separator character, the
			 * server MUST fail the request with
			 * STATUS_INVALID_PARAMETER.
			 */
			if (in_name[0] == '\\' || in_name[0] == '/') {
				tevent_req_nterror(req,
					NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			status = SMB_VFS_CREATE_FILE(smb1req->conn,
						     smb1req,
						     0, /* root_dir_fid */
						     smb_fname,
						     in_desired_access,
						     in_share_access,
						     in_create_disposition,
						     in_create_options,
						     in_file_attributes,
						     map_smb2_oplock_levels_to_samba(requested_oplock_level),
						     lease_ptr,
						     allocation_size,
						     0, /* private_flags */
						     sec_desc,
						     ea_list,
						     &result,
						     &info,
						     &in_context_blobs,
						     state->out_context_blobs);
			if (!NT_STATUS_IS_OK(status)) {
				if (open_was_deferred(smb1req->xconn, smb1req->mid)) {
					SMBPROFILE_IOBYTES_ASYNC_SET_IDLE(smb2req->profile);
					return req;
				}
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
			op = result->op;
		}

		/*
		 * here we have op == result->op
		 */

		DEBUG(10, ("smbd_smb2_create_send: "
			   "response construction phase\n"));

		if (mxac) {
			NTTIME last_write_time;

			last_write_time = unix_timespec_to_nt_time(
						 result->fsp_name->st.st_ex_mtime);
			if (last_write_time != max_access_time) {
				uint8_t p[8];
				uint32_t max_access_granted;
				DATA_BLOB blob = data_blob_const(p, sizeof(p));

				status = smbd_calculate_access_mask(smb1req->conn,
							result->fsp_name,
							false,
							SEC_FLAG_MAXIMUM_ALLOWED,
							&max_access_granted);

				SIVAL(p, 0, NT_STATUS_V(status));
				SIVAL(p, 4, max_access_granted);

				status = smb2_create_blob_add(
				    state->out_context_blobs,
				    state->out_context_blobs,
				    SMB2_CREATE_TAG_MXAC,
				    blob);
				if (!NT_STATUS_IS_OK(status)) {
					tevent_req_nterror(req, status);
					return tevent_req_post(req, ev);
				}
			}
		}

		if (!replay_operation && durable_requested &&
		    (fsp_lease_type(result) & SMB2_LEASE_HANDLE))
		{
			status = SMB_VFS_DURABLE_COOKIE(result,
						op,
						&op->global->backend_cookie);
			if (!NT_STATUS_IS_OK(status)) {
				op->global->backend_cookie = data_blob_null;
			}
		}
		if (!replay_operation && op->global->backend_cookie.length > 0)
		{
			update_open = true;

			op->global->durable = true;
			op->global->durable_timeout_msec = durable_timeout_msec;
		}

		if (update_open) {
			op->global->create_guid = _create_guid;
			if (need_replay_cache) {
				op->flags |= SMBXSRV_OPEN_NEED_REPLAY_CACHE;
			}

			status = smbXsrv_open_update(op);
			DEBUG(10, ("smb2_create_send: smbXsrv_open_update "
				   "returned %s\n",
				   nt_errstr(status)));
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}

		if (dhnq && op->global->durable) {
			uint8_t p[8] = { 0, };
			DATA_BLOB blob = data_blob_const(p, sizeof(p));

			status = smb2_create_blob_add(state->out_context_blobs,
						      state->out_context_blobs,
						      SMB2_CREATE_TAG_DHNQ,
						      blob);
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}

		if (dh2q && op->global->durable &&
		    /*
		     * For replay operations, we return the dh2q blob
		     * in the case of oplocks not based on the state of
		     * the open, but on whether it could have been granted
		     * for the request data. In the case of leases instead,
		     * the state of the open is used...
		     */
		    (!replay_operation ||
		     in_oplock_level == SMB2_OPLOCK_LEVEL_BATCH ||
		     in_oplock_level == SMB2_OPLOCK_LEVEL_LEASE))
		{
			uint8_t p[8] = { 0, };
			DATA_BLOB blob = data_blob_const(p, sizeof(p));
			uint32_t durable_v2_response_flags = 0;

			SIVAL(p, 0, op->global->durable_timeout_msec);
			SIVAL(p, 4, durable_v2_response_flags);

			status = smb2_create_blob_add(state->out_context_blobs,
						      state->out_context_blobs,
						      SMB2_CREATE_TAG_DH2Q,
						      blob);
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}

		if (qfid) {
			uint8_t p[32];
			uint64_t file_index = get_FileIndex(result->conn,
							&result->fsp_name->st);
			DATA_BLOB blob = data_blob_const(p, sizeof(p));

			ZERO_STRUCT(p);

			/* From conversations with Microsoft engineers at
			   the MS plugfest. The first 8 bytes are the "volume index"
			   == inode, the second 8 bytes are the "volume id",
			   == dev. This will be updated in the SMB2 doc. */
			SBVAL(p, 0, file_index);
			SIVAL(p, 8, result->fsp_name->st.st_ex_dev);/* FileIndexHigh */

			status = smb2_create_blob_add(state->out_context_blobs,
						      state->out_context_blobs,
						      SMB2_CREATE_TAG_QFID,
						      blob);
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}

		if ((rqls != NULL) && (result->oplock_type == LEASE_OPLOCK)) {
			uint8_t buf[52];

			lease = result->lease->lease;

			lease_len = sizeof(buf);
			if (lease.lease_version == 1) {
				lease_len = 32;
			}

			if (!smb2_lease_push(&lease, buf, lease_len)) {
				tevent_req_nterror(
					req, NT_STATUS_INTERNAL_ERROR);
				return tevent_req_post(req, ev);
			}

			status = smb2_create_blob_add(
				state, state->out_context_blobs,
				SMB2_CREATE_TAG_RQLS,
				data_blob_const(buf, lease_len));
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}
	}

	smb2req->compat_chain_fsp = smb1req->chain_fsp;

	if (replay_operation) {
		state->out_oplock_level = in_oplock_level;
	} else if (lp_fake_oplocks(SNUM(smb2req->tcon->compat))) {
		state->out_oplock_level	= in_oplock_level;
	} else {
		state->out_oplock_level	= map_samba_oplock_levels_to_smb2(result->oplock_type);
	}

	if ((in_create_disposition == FILE_SUPERSEDE)
	    && (info == FILE_WAS_OVERWRITTEN)) {
		state->out_create_action = FILE_WAS_SUPERSEDED;
	} else {
		state->out_create_action = info;
	}
	result->op->create_action = state->out_create_action;
	state->out_file_attributes = dos_mode(result->conn,
					   result->fsp_name);

	state->out_creation_ts = get_create_timespec(smb1req->conn,
					result, result->fsp_name);
	state->out_last_access_ts = result->fsp_name->st.st_ex_atime;
	state->out_last_write_ts = result->fsp_name->st.st_ex_mtime;
	state->out_change_ts = get_change_timespec(smb1req->conn,
					result, result->fsp_name);

	if (lp_dos_filetime_resolution(SNUM(smb2req->tcon->compat))) {
		dos_filetime_timespec(&state->out_creation_ts);
		dos_filetime_timespec(&state->out_last_access_ts);
		dos_filetime_timespec(&state->out_last_write_ts);
		dos_filetime_timespec(&state->out_change_ts);
	}

	state->out_allocation_size =
			SMB_VFS_GET_ALLOC_SIZE(smb1req->conn, result,
					       &(result->fsp_name->st));
	state->out_end_of_file = result->fsp_name->st.st_ex_size;
	if (state->out_file_attributes == 0) {
		state->out_file_attributes = FILE_ATTRIBUTE_NORMAL;
	}
	state->out_file_id_persistent = result->op->global->open_persistent_id;
	state->out_file_id_volatile = result->op->global->open_volatile_id;

	DEBUG(10,("smbd_smb2_create_send: %s - %s\n",
		  fsp_str_dbg(result), fsp_fnum_dbg(result)));

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS smbd_smb2_create_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			uint8_t *out_oplock_level,
			uint32_t *out_create_action,
			struct timespec *out_creation_ts,
			struct timespec *out_last_access_ts,
			struct timespec *out_last_write_ts,
			struct timespec *out_change_ts,
			uint64_t *out_allocation_size,
			uint64_t *out_end_of_file,
			uint32_t *out_file_attributes,
			uint64_t *out_file_id_persistent,
			uint64_t *out_file_id_volatile,
			struct smb2_create_blobs *out_context_blobs)
{
	NTSTATUS status;
	struct smbd_smb2_create_state *state = tevent_req_data(req,
					       struct smbd_smb2_create_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_oplock_level	= state->out_oplock_level;
	*out_create_action	= state->out_create_action;
	*out_creation_ts	= state->out_creation_ts;
	*out_last_access_ts	= state->out_last_access_ts;
	*out_last_write_ts	= state->out_last_write_ts;
	*out_change_ts		= state->out_change_ts;
	*out_allocation_size	= state->out_allocation_size;
	*out_end_of_file	= state->out_end_of_file;
	*out_file_attributes	= state->out_file_attributes;
	*out_file_id_persistent	= state->out_file_id_persistent;
	*out_file_id_volatile	= state->out_file_id_volatile;
	*out_context_blobs	= *(state->out_context_blobs);

	talloc_steal(mem_ctx, state->out_context_blobs->blobs);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*********************************************************
 Code for dealing with deferred opens.
*********************************************************/

bool get_deferred_open_message_state_smb2(struct smbd_smb2_request *smb2req,
			struct timeval *p_request_time,
			struct deferred_open_record **open_rec)
{
	struct smbd_smb2_create_state *state = NULL;
	struct tevent_req *req = NULL;

	if (!smb2req) {
		return false;
	}
	req = smb2req->subreq;
	if (!req) {
		return false;
	}
	state = tevent_req_data(req, struct smbd_smb2_create_state);
	if (!state) {
		return false;
	}
	if (!state->open_was_deferred) {
		return false;
	}
	if (p_request_time) {
		*p_request_time = state->request_time;
	}
	if (open_rec != NULL) {
		*open_rec = state->open_rec;
	}
	return true;
}

/*********************************************************
 Re-process this call early - requested by message or
 close.
*********************************************************/

static struct smbd_smb2_request *find_open_smb2req(
	struct smbXsrv_connection *xconn, uint64_t mid)
{
	struct smbd_smb2_request *smb2req;

	for (smb2req = xconn->smb2.requests; smb2req; smb2req = smb2req->next) {
		uint64_t message_id;
		if (smb2req->subreq == NULL) {
			/* This message has been processed. */
			continue;
		}
		if (!tevent_req_is_in_progress(smb2req->subreq)) {
			/* This message has been processed. */
			continue;
		}
		message_id = get_mid_from_smb2req(smb2req);
		if (message_id == mid) {
			return smb2req;
		}
	}
	return NULL;
}

bool open_was_deferred_smb2(struct smbXsrv_connection *xconn, uint64_t mid)
{
	struct smbd_smb2_create_state *state = NULL;
	struct smbd_smb2_request *smb2req;

	smb2req = find_open_smb2req(xconn, mid);

	if (!smb2req) {
		DEBUG(10,("open_was_deferred_smb2: mid %llu smb2req == NULL\n",
			(unsigned long long)mid));
		return false;
	}
	if (!smb2req->subreq) {
		return false;
	}
	if (!tevent_req_is_in_progress(smb2req->subreq)) {
		return false;
	}
	state = tevent_req_data(smb2req->subreq,
			struct smbd_smb2_create_state);
	if (!state) {
		return false;
	}
	/* It's not in progress if there's no timeout event. */
	if (!state->open_was_deferred) {
		return false;
	}

	DEBUG(10,("open_was_deferred_smb2: mid = %llu\n",
			(unsigned long long)mid));

	return true;
}

static void remove_deferred_open_message_smb2_internal(struct smbd_smb2_request *smb2req,
							uint64_t mid)
{
	struct smbd_smb2_create_state *state = NULL;

	if (!smb2req->subreq) {
		return;
	}
	if (!tevent_req_is_in_progress(smb2req->subreq)) {
		return;
	}
	state = tevent_req_data(smb2req->subreq,
			struct smbd_smb2_create_state);
	if (!state) {
		return;
	}

	DEBUG(10,("remove_deferred_open_message_smb2_internal: "
		"mid %llu\n",
		(unsigned long long)mid ));

	state->open_was_deferred = false;
	/* Ensure we don't have any outstanding timer event. */
	TALLOC_FREE(state->te);
	/* Ensure we don't have any outstanding immediate event. */
	TALLOC_FREE(state->im);
}

void remove_deferred_open_message_smb2(
	struct smbXsrv_connection *xconn, uint64_t mid)
{
	struct smbd_smb2_request *smb2req;

	smb2req = find_open_smb2req(xconn, mid);

	if (!smb2req) {
		DEBUG(10,("remove_deferred_open_message_smb2: "
			"can't find mid %llu\n",
			(unsigned long long)mid ));
		return;
	}
	remove_deferred_open_message_smb2_internal(smb2req, mid);
}

static void smbd_smb2_create_request_dispatch_immediate(struct tevent_context *ctx,
					struct tevent_immediate *im,
					void *private_data)
{
	struct smbd_smb2_request *smb2req = talloc_get_type_abort(private_data,
					struct smbd_smb2_request);
	uint64_t mid = get_mid_from_smb2req(smb2req);
	NTSTATUS status;

	DEBUG(10,("smbd_smb2_create_request_dispatch_immediate: "
		"re-dispatching mid %llu\n",
		(unsigned long long)mid ));

	status = smbd_smb2_request_dispatch(smb2req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(smb2req->xconn,
						 nt_errstr(status));
		return;
	}
}

bool schedule_deferred_open_message_smb2(
	struct smbXsrv_connection *xconn, uint64_t mid)
{
	struct smbd_smb2_create_state *state = NULL;
	struct smbd_smb2_request *smb2req;

	smb2req = find_open_smb2req(xconn, mid);

	if (!smb2req) {
		DEBUG(10,("schedule_deferred_open_message_smb2: "
			"can't find mid %llu\n",
			(unsigned long long)mid ));
		return false;
	}
	if (!smb2req->subreq) {
		return false;
	}
	if (!tevent_req_is_in_progress(smb2req->subreq)) {
		return false;
	}
	state = tevent_req_data(smb2req->subreq,
			struct smbd_smb2_create_state);
	if (!state) {
		return false;
	}

	/* Ensure we don't have any outstanding timer event. */
	TALLOC_FREE(state->te);
	/* Ensure we don't have any outstanding immediate event. */
	TALLOC_FREE(state->im);

	/*
	 * This is subtle. We must null out the callback
	 * before rescheduling, else the first call to
	 * tevent_req_nterror() causes the _receive()
	 * function to be called, this causing tevent_req_post()
	 * to crash.
	 */
	tevent_req_set_callback(smb2req->subreq, NULL, NULL);

	state->im = tevent_create_immediate(smb2req);
	if (!state->im) {
		smbd_server_connection_terminate(smb2req->xconn,
			nt_errstr(NT_STATUS_NO_MEMORY));
		return false;
	}

	DEBUG(10,("schedule_deferred_open_message_smb2: "
		"re-processing mid %llu\n",
		(unsigned long long)mid ));

	tevent_schedule_immediate(state->im,
			smb2req->sconn->ev_ctx,
			smbd_smb2_create_request_dispatch_immediate,
			smb2req);

	return true;
}

static bool smbd_smb2_create_cancel(struct tevent_req *req)
{
	struct smbd_smb2_request *smb2req = NULL;
	struct smbd_smb2_create_state *state = tevent_req_data(req,
				struct smbd_smb2_create_state);
	uint64_t mid;

	if (!state) {
		return false;
	}

	if (!state->smb2req) {
		return false;
	}

	smb2req = state->smb2req;
	mid = get_mid_from_smb2req(smb2req);

	if (is_deferred_open_async(state->open_rec)) {
		/* Can't cancel an async create. */
		return false;
	}

	remove_deferred_open_message_smb2_internal(smb2req, mid);

	tevent_req_defer_callback(req, smb2req->sconn->ev_ctx);
	tevent_req_nterror(req, NT_STATUS_CANCELLED);
	return true;
}

bool push_deferred_open_message_smb2(struct smbd_smb2_request *smb2req,
                                struct timeval request_time,
                                struct timeval timeout,
				struct file_id id,
				struct deferred_open_record *open_rec)
{
	struct tevent_req *req = NULL;
	struct smbd_smb2_create_state *state = NULL;
	struct timeval end_time;

	if (!smb2req) {
		return false;
	}
	req = smb2req->subreq;
	if (!req) {
		return false;
	}
	state = tevent_req_data(req, struct smbd_smb2_create_state);
	if (!state) {
		return false;
	}
	state->id = id;
	state->request_time = request_time;
	state->open_rec = talloc_move(state, &open_rec);

	/* Re-schedule us to retry on timer expiry. */
	end_time = timeval_sum(&request_time, &timeout);

	DEBUG(10,("push_deferred_open_message_smb2: "
		"timeout at %s\n",
		timeval_string(talloc_tos(),
				&end_time,
				true) ));

	state->open_was_deferred = true;

	/* allow this request to be canceled */
	tevent_req_set_cancel_fn(req, smbd_smb2_create_cancel);

	return true;
}
