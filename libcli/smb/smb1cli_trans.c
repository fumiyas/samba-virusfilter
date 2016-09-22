/*
   Unix SMB/CIFS implementation.
   client transaction calls
   Copyright (C) Andrew Tridgell 1994-1998

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
#include "system/network.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/smb/smbXcli_base.h"

struct trans_recvblob {
	uint8_t *data;
	uint32_t max, total, received;
};

struct smb1cli_trans_state {
	struct smbXcli_conn *conn;
	struct tevent_context *ev;
	uint8_t cmd;
	uint8_t additional_flags;
	uint8_t clear_flags;
	uint16_t additional_flags2;
	uint16_t clear_flags2;
	uint32_t timeout_msec;
	uint16_t mid;
	uint32_t pid;
	struct smbXcli_tcon *tcon;
	struct smbXcli_session *session;
	const char *pipe_name;
	uint8_t *pipe_name_conv;
	size_t pipe_name_conv_len;
	uint16_t fid;
	uint16_t function;
	int flags;
	uint16_t *setup;
	uint8_t num_setup, max_setup;
	uint8_t *param;
	uint32_t num_param, param_sent;
	uint8_t *data;
	uint32_t num_data, data_sent;

	uint8_t num_rsetup;
	uint16_t *rsetup;
	struct trans_recvblob rparam;
	struct trans_recvblob rdata;
	uint16_t recv_flags2;

	struct iovec iov[6];
	uint8_t pad[4];
	uint8_t zero_pad[4];
	uint16_t vwv[32];

	NTSTATUS status;

	struct tevent_req *primary_subreq;
};

static void smb1cli_trans_cleanup_primary(struct smb1cli_trans_state *state)
{
	if (state->primary_subreq) {
		smb1cli_req_set_mid(state->primary_subreq, 0);
		smbXcli_req_unset_pending(state->primary_subreq);
		TALLOC_FREE(state->primary_subreq);
	}
}

static int smb1cli_trans_state_destructor(struct smb1cli_trans_state *state)
{
	smb1cli_trans_cleanup_primary(state);
	return 0;
}

static NTSTATUS smb1cli_pull_trans(uint8_t *inhdr,
				   uint8_t wct,
				   uint16_t *vwv,
				   uint32_t vwv_ofs,
				   uint32_t num_bytes,
				   uint8_t *bytes,
				   uint32_t bytes_ofs,
				   uint8_t smb_cmd, bool expect_first_reply,
				   uint8_t *pnum_setup, uint16_t **psetup,
				   uint32_t *ptotal_param, uint32_t *pnum_param,
				   uint32_t *pparam_disp, uint8_t **pparam,
				   uint32_t *ptotal_data, uint32_t *pnum_data,
				   uint32_t *pdata_disp, uint8_t **pdata)
{
	uint32_t param_ofs, data_ofs;
	uint8_t expected_num_setup;
	uint32_t max_bytes = UINT32_MAX - bytes_ofs;
	uint32_t bytes_end;

	if (num_bytes > max_bytes) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	bytes_end = bytes_ofs + num_bytes;

	if (expect_first_reply) {
		if ((wct != 0) || (num_bytes != 0)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		return NT_STATUS_OK;
	}

	switch (smb_cmd) {
	case SMBtrans:
	case SMBtrans2:
		if (wct < 10) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		expected_num_setup = wct - 10;
		*ptotal_param	= SVAL(vwv + 0, 0);
		*ptotal_data	= SVAL(vwv + 1, 0);
		*pnum_param	= SVAL(vwv + 3, 0);
		param_ofs	= SVAL(vwv + 4, 0);
		*pparam_disp	= SVAL(vwv + 5, 0);
		*pnum_data	= SVAL(vwv + 6, 0);
		data_ofs	= SVAL(vwv + 7, 0);
		*pdata_disp	= SVAL(vwv + 8, 0);
		*pnum_setup	= CVAL(vwv + 9, 0);
		if (expected_num_setup < (*pnum_setup)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		*psetup = vwv + 10;

		break;
	case SMBnttrans:
		if (wct < 18) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		expected_num_setup = wct - 18;
		*ptotal_param	= IVAL(vwv, 3);
		*ptotal_data	= IVAL(vwv, 7);
		*pnum_param	= IVAL(vwv, 11);
		param_ofs	= IVAL(vwv, 15);
		*pparam_disp	= IVAL(vwv, 19);
		*pnum_data	= IVAL(vwv, 23);
		data_ofs	= IVAL(vwv, 27);
		*pdata_disp	= IVAL(vwv, 31);
		*pnum_setup	= CVAL(vwv, 35);
		if (expected_num_setup < (*pnum_setup)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		*psetup		= vwv + 18;
		break;

	default:
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * Check for buffer overflows. data_ofs needs to be checked against
	 * the incoming buffer length, data_disp against the total
	 * length. Likewise for param_ofs/param_disp.
	 */

	if (smb_buffer_oob(bytes_end, param_ofs, *pnum_param)
	    || smb_buffer_oob(*ptotal_param, *pparam_disp, *pnum_param)
	    || smb_buffer_oob(bytes_end, data_ofs, *pnum_data)
	    || smb_buffer_oob(*ptotal_data, *pdata_disp, *pnum_data)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	*pparam = (uint8_t *)inhdr + param_ofs;
	*pdata = (uint8_t *)inhdr + data_ofs;

	return NT_STATUS_OK;
}

static NTSTATUS smb1cli_trans_pull_blob(TALLOC_CTX *mem_ctx,
					struct trans_recvblob *blob,
					uint32_t total, uint32_t thistime,
					uint8_t *buf, uint32_t displacement)
{
	if (blob->data == NULL) {
		if (total > blob->max) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		blob->total = total;
		blob->data = talloc_array(mem_ctx, uint8_t, total);
		if (blob->data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (total > blob->total) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (thistime) {
		memcpy(blob->data + displacement, buf, thistime);
		blob->received += thistime;
	}

	return NT_STATUS_OK;
}

static void smb1cli_trans_format(struct smb1cli_trans_state *state,
				 uint8_t *pwct,
				 int *piov_count)
{
	uint8_t wct = 0;
	struct iovec *iov = state->iov;
	uint8_t *pad = state->pad;
	uint16_t *vwv = state->vwv;
	uint32_t param_offset;
	uint32_t this_param = 0;
	uint32_t param_pad;
	uint32_t data_offset;
	uint32_t this_data = 0;
	uint32_t data_pad;
	uint32_t useable_space;
	uint8_t cmd;
	uint32_t max_trans = smb1cli_conn_max_xmit(state->conn);

	cmd = state->cmd;

	if ((state->param_sent != 0) || (state->data_sent != 0)) {
		/* The secondary commands are one after the primary ones */
		cmd += 1;
	}

	param_offset = MIN_SMB_SIZE;

	switch (cmd) {
	case SMBtrans:
		if (smbXcli_conn_use_unicode(state->conn)) {
			pad[0] = 0;
			iov[0].iov_base = (void *)pad;
			iov[0].iov_len = 1;
			param_offset += 1;
			iov += 1;
		}
		iov[0].iov_base = (void *)state->pipe_name_conv;
		iov[0].iov_len = state->pipe_name_conv_len;
		wct = 14 + state->num_setup;
		param_offset += iov[0].iov_len;
		iov += 1;
		break;
	case SMBtrans2:
		pad[0] = 0;
		pad[1] = 'D'; /* Copy this from "old" 3.0 behaviour */
		pad[2] = ' ';
		iov[0].iov_base = (void *)pad;
		iov[0].iov_len = 3;
		wct = 14 + state->num_setup;
		param_offset += 3;
		iov += 1;
		break;
	case SMBtranss:
		wct = 8;
		break;
	case SMBtranss2:
		wct = 9;
		break;
	case SMBnttrans:
		wct = 19 + state->num_setup;
		break;
	case SMBnttranss:
		wct = 18;
		break;
	}

	param_offset += wct * sizeof(uint16_t);
	useable_space = max_trans - param_offset;

	param_pad = param_offset % 4;
	if (param_pad > 0) {
		param_pad = MIN(param_pad, useable_space);
		iov[0].iov_base = (void *)state->zero_pad;
		iov[0].iov_len = param_pad;
		iov += 1;
		param_offset += param_pad;
	}
	useable_space = max_trans - param_offset;

	if (state->param_sent < state->num_param) {
		this_param = MIN(state->num_param - state->param_sent,
				 useable_space);
		iov[0].iov_base = (void *)(state->param + state->param_sent);
		iov[0].iov_len = this_param;
		iov += 1;
	}

	data_offset = param_offset + this_param;
	useable_space = max_trans - data_offset;

	data_pad = data_offset % 4;
	if (data_pad > 0) {
		data_pad = MIN(data_pad, useable_space);
		iov[0].iov_base = (void *)state->zero_pad;
		iov[0].iov_len = data_pad;
		iov += 1;
		data_offset += data_pad;
	}
	useable_space = max_trans - data_offset;

	if (state->data_sent < state->num_data) {
		this_data = MIN(state->num_data - state->data_sent,
				useable_space);
		iov[0].iov_base = (void *)(state->data + state->data_sent);
		iov[0].iov_len = this_data;
		iov += 1;
	}

	DEBUG(10, ("num_setup=%u, max_setup=%u, "
		   "param_total=%u, this_param=%u, max_param=%u, "
		   "data_total=%u, this_data=%u, max_data=%u, "
		   "param_offset=%u, param_pad=%u, param_disp=%u, "
		   "data_offset=%u, data_pad=%u, data_disp=%u\n",
		   (unsigned)state->num_setup, (unsigned)state->max_setup,
		   (unsigned)state->num_param, (unsigned)this_param,
		   (unsigned)state->rparam.max,
		   (unsigned)state->num_data, (unsigned)this_data,
		   (unsigned)state->rdata.max,
		   (unsigned)param_offset, (unsigned)param_pad,
		   (unsigned)state->param_sent,
		   (unsigned)data_offset, (unsigned)data_pad,
		   (unsigned)state->data_sent));

	switch (cmd) {
	case SMBtrans:
	case SMBtrans2:
		SSVAL(vwv + 0, 0, state->num_param);
		SSVAL(vwv + 1, 0, state->num_data);
		SSVAL(vwv + 2, 0, state->rparam.max);
		SSVAL(vwv + 3, 0, state->rdata.max);
		SCVAL(vwv + 4, 0, state->max_setup);
		SCVAL(vwv + 4, 1, 0);	/* reserved */
		SSVAL(vwv + 5, 0, state->flags);
		SIVAL(vwv + 6, 0, 0);	/* timeout */
		SSVAL(vwv + 8, 0, 0);	/* reserved */
		SSVAL(vwv + 9, 0, this_param);
		SSVAL(vwv +10, 0, param_offset);
		SSVAL(vwv +11, 0, this_data);
		SSVAL(vwv +12, 0, data_offset);
		SCVAL(vwv +13, 0, state->num_setup);
		SCVAL(vwv +13, 1, 0);	/* reserved */
		memcpy(vwv + 14, state->setup,
		       sizeof(uint16_t) * state->num_setup);
		break;
	case SMBtranss:
	case SMBtranss2:
		SSVAL(vwv + 0, 0, state->num_param);
		SSVAL(vwv + 1, 0, state->num_data);
		SSVAL(vwv + 2, 0, this_param);
		SSVAL(vwv + 3, 0, param_offset);
		SSVAL(vwv + 4, 0, state->param_sent);
		SSVAL(vwv + 5, 0, this_data);
		SSVAL(vwv + 6, 0, data_offset);
		SSVAL(vwv + 7, 0, state->data_sent);
		if (cmd == SMBtranss2) {
			SSVAL(vwv + 8, 0, state->fid);
		}
		break;
	case SMBnttrans:
		SCVAL(vwv + 0, 0, state->max_setup);
		SSVAL(vwv + 0, 1, 0); /* reserved */
		SIVAL(vwv + 1, 1, state->num_param);
		SIVAL(vwv + 3, 1, state->num_data);
		SIVAL(vwv + 5, 1, state->rparam.max);
		SIVAL(vwv + 7, 1, state->rdata.max);
		SIVAL(vwv + 9, 1, this_param);
		SIVAL(vwv +11, 1, param_offset);
		SIVAL(vwv +13, 1, this_data);
		SIVAL(vwv +15, 1, data_offset);
		SCVAL(vwv +17, 1, state->num_setup);
		SSVAL(vwv +18, 0, state->function);
		memcpy(vwv + 19, state->setup,
		       sizeof(uint16_t) * state->num_setup);
		break;
	case SMBnttranss:
		SSVAL(vwv + 0, 0, 0); /* reserved */
		SCVAL(vwv + 1, 0, 0); /* reserved */
		SIVAL(vwv + 1, 1, state->num_param);
		SIVAL(vwv + 3, 1, state->num_data);
		SIVAL(vwv + 5, 1, this_param);
		SIVAL(vwv + 7, 1, param_offset);
		SIVAL(vwv + 9, 1, state->param_sent);
		SIVAL(vwv +11, 1, this_data);
		SIVAL(vwv +13, 1, data_offset);
		SIVAL(vwv +15, 1, state->data_sent);
		SCVAL(vwv +17, 1, 0); /* reserved */
		break;
	}

	state->param_sent += this_param;
	state->data_sent += this_data;

	*pwct = wct;
	*piov_count = iov - state->iov;
}

static bool smb1cli_trans_cancel(struct tevent_req *req);
static void smb1cli_trans_done(struct tevent_req *subreq);

struct tevent_req *smb1cli_trans_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct smbXcli_conn *conn, uint8_t cmd,
	uint8_t additional_flags, uint8_t clear_flags,
	uint16_t additional_flags2, uint16_t clear_flags2,
	uint32_t timeout_msec,
	uint32_t pid,
	struct smbXcli_tcon *tcon,
	struct smbXcli_session *session,
	const char *pipe_name, uint16_t fid, uint16_t function, int flags,
	uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
	uint8_t *param, uint32_t num_param, uint32_t max_param,
	uint8_t *data, uint32_t num_data, uint32_t max_data)
{
	struct tevent_req *req, *subreq;
	struct smb1cli_trans_state *state;
	int iov_count;
	uint8_t wct;
	NTSTATUS status;
	charset_t charset;

	req = tevent_req_create(mem_ctx, &state,
				struct smb1cli_trans_state);
	if (req == NULL) {
		return NULL;
	}

	if ((cmd == SMBtrans) || (cmd == SMBtrans2)) {
		if ((num_param > 0xffff) || (max_param > 0xffff)
		    || (num_data > 0xffff) || (max_data > 0xffff)) {
			DEBUG(3, ("Attempt to send invalid trans2 request "
				  "(setup %u, params %u/%u, data %u/%u)\n",
				  (unsigned)num_setup,
				  (unsigned)num_param, (unsigned)max_param,
				  (unsigned)num_data, (unsigned)max_data));
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return tevent_req_post(req, ev);
		}
	}

	/*
	 * The largest wct will be for nttrans (19+num_setup). Make sure we
	 * don't overflow state->vwv in smb1cli_trans_format.
	 */

	if ((num_setup + 19) > ARRAY_SIZE(state->vwv)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	state->conn = conn;
	state->ev = ev;
	state->cmd = cmd;
	state->additional_flags = additional_flags;
	state->clear_flags = clear_flags;
	state->additional_flags2 = additional_flags2;
	state->clear_flags2 = clear_flags2;
	state->timeout_msec = timeout_msec;
	state->flags = flags;
	state->num_rsetup = 0;
	state->rsetup = NULL;
	state->pid = pid;
	state->tcon = tcon;
	state->session = session;
	ZERO_STRUCT(state->rparam);
	ZERO_STRUCT(state->rdata);

	if (smbXcli_conn_use_unicode(conn)) {
		charset = CH_UTF16LE;
	} else {
		charset = CH_DOS;
	}

	if ((pipe_name != NULL)
	    && (!convert_string_talloc(state, CH_UNIX, charset,
				       pipe_name, strlen(pipe_name) + 1,
				       &state->pipe_name_conv,
				       &state->pipe_name_conv_len))) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}
	state->fid = fid;	/* trans2 */
	state->function = function; /* nttrans */

	state->setup = setup;
	state->num_setup = num_setup;
	state->max_setup = max_setup;

	state->param = param;
	state->num_param = num_param;
	state->param_sent = 0;
	state->rparam.max = max_param;

	state->data = data;
	state->num_data = num_data;
	state->data_sent = 0;
	state->rdata.max = max_data;

	smb1cli_trans_format(state, &wct, &iov_count);

	subreq = smb1cli_req_create(state, ev, conn, cmd,
				    state->additional_flags,
				    state->clear_flags,
				    state->additional_flags2,
				    state->clear_flags2,
				    state->timeout_msec,
				    state->pid,
				    state->tcon,
				    state->session,
				    wct, state->vwv,
				    iov_count, state->iov);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	status = smb1cli_req_chain_submit(&subreq, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, state->ev);
	}
	tevent_req_set_callback(subreq, smb1cli_trans_done, req);

	/*
	 * Now get the MID of the primary request
	 * and mark it as persistent. This means
	 * we will able to send and receive multiple
	 * SMB pdus using this MID in both directions
	 * (including correct SMB signing).
	 */
	state->mid = smb1cli_req_mid(subreq);
	smb1cli_req_set_mid(subreq, state->mid);
	state->primary_subreq = subreq;
	talloc_set_destructor(state, smb1cli_trans_state_destructor);

	tevent_req_set_cancel_fn(req, smb1cli_trans_cancel);

	return req;
}

static bool smb1cli_trans_cancel(struct tevent_req *req)
{
	struct smb1cli_trans_state *state =
		tevent_req_data(req,
		struct smb1cli_trans_state);

	if (state->primary_subreq == NULL) {
		return false;
	}

	return tevent_req_cancel(state->primary_subreq);
}

static void smb1cli_trans_done2(struct tevent_req *subreq);

static void smb1cli_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb1cli_trans_state *state =
		tevent_req_data(req,
		struct smb1cli_trans_state);
	NTSTATUS status;
	bool sent_all;
	struct iovec *recv_iov = NULL;
	uint8_t *inhdr;
	uint8_t wct;
	uint16_t *vwv;
	uint32_t vwv_ofs;
	uint32_t num_bytes;
	uint8_t *bytes;
	uint32_t bytes_ofs;
	uint8_t num_setup	= 0;
	uint16_t *setup		= NULL;
	uint32_t total_param	= 0;
	uint32_t num_param	= 0;
	uint32_t param_disp	= 0;
	uint32_t total_data	= 0;
	uint32_t num_data	= 0;
	uint32_t data_disp	= 0;
	uint8_t *param		= NULL;
	uint8_t *data		= NULL;

	status = smb1cli_req_recv(subreq, state,
				  &recv_iov,
				  &inhdr,
				  &wct,
				  &vwv,
				  &vwv_ofs,
				  &num_bytes,
				  &bytes,
				  &bytes_ofs,
				  NULL, /* pinbuf */
				  NULL, 0); /* expected */
	/*
	 * Do not TALLOC_FREE(subreq) here, we might receive more than
	 * one response for the same mid.
	 */

	/*
	 * We can receive something like STATUS_MORE_ENTRIES, so don't use
	 * !NT_STATUS_IS_OK(status) here.
	 */

	if (NT_STATUS_IS_ERR(status)) {
		goto fail;
	}

	if (recv_iov == NULL) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}
	state->status = status;

	sent_all = ((state->param_sent == state->num_param)
		    && (state->data_sent == state->num_data));

	status = smb1cli_pull_trans(
		inhdr, wct, vwv, vwv_ofs,
		num_bytes, bytes, bytes_ofs,
		state->cmd, !sent_all, &num_setup, &setup,
		&total_param, &num_param, &param_disp, &param,
		&total_data, &num_data, &data_disp, &data);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (!sent_all) {
		int iov_count;
		struct tevent_req *subreq2;

		smb1cli_trans_format(state, &wct, &iov_count);

		subreq2 = smb1cli_req_create(state, state->ev, state->conn,
					     state->cmd + 1,
					     state->additional_flags,
					     state->clear_flags,
					     state->additional_flags2,
					     state->clear_flags2,
					     state->timeout_msec,
					     state->pid,
					     state->tcon,
					     state->session,
					     wct, state->vwv,
					     iov_count, state->iov);
		if (tevent_req_nomem(subreq2, req)) {
			return;
		}
		smb1cli_req_set_mid(subreq2, state->mid);

		status = smb1cli_req_chain_submit(&subreq2, 1);

		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		tevent_req_set_callback(subreq2, smb1cli_trans_done2, req);

		return;
	}

	status = smb1cli_trans_pull_blob(
		state, &state->rparam, total_param, num_param, param,
		param_disp);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Pulling params failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	status = smb1cli_trans_pull_blob(
		state, &state->rdata, total_data, num_data, data,
		data_disp);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Pulling data failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	if ((state->rparam.total == state->rparam.received)
	    && (state->rdata.total == state->rdata.received)) {
		state->recv_flags2 = SVAL(inhdr, HDR_FLG2);
		smb1cli_trans_cleanup_primary(state);
		tevent_req_done(req);
		return;
	}

	TALLOC_FREE(recv_iov);

	return;

 fail:
	smb1cli_trans_cleanup_primary(state);
	tevent_req_nterror(req, status);
}

static void smb1cli_trans_done2(struct tevent_req *subreq2)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq2,
		struct tevent_req);
	struct smb1cli_trans_state *state =
		tevent_req_data(req,
		struct smb1cli_trans_state);
	NTSTATUS status;
	bool sent_all;
	uint32_t seqnum;

	/*
	 * First backup the seqnum of the secondary request
	 * and attach it to the primary request.
	 */
	seqnum = smb1cli_req_seqnum(subreq2);
	smb1cli_req_set_seqnum(state->primary_subreq, seqnum);

	/* This was a one way request */
	status = smb1cli_req_recv(subreq2, state,
				  NULL, /* recv_iov */
				  NULL, /* phdr */
				  NULL, /* pwct */
				  NULL, /* pvwv */
				  NULL, /* pvwv_offset */
				  NULL, /* pnum_bytes */
				  NULL, /* pbytes */
				  NULL, /* pbytes_offset */
				  NULL, /* pinbuf */
				  NULL, 0); /* expected */
	TALLOC_FREE(subreq2);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	sent_all = ((state->param_sent == state->num_param)
		    && (state->data_sent == state->num_data));

	if (!sent_all) {
		uint8_t wct;
		int iov_count;

		smb1cli_trans_format(state, &wct, &iov_count);

		subreq2 = smb1cli_req_create(state, state->ev, state->conn,
					     state->cmd + 1,
					     state->additional_flags,
					     state->clear_flags,
					     state->additional_flags2,
					     state->clear_flags2,
					     state->timeout_msec,
					     state->pid,
					     state->tcon,
					     state->session,
					     wct, state->vwv,
					     iov_count, state->iov);
		if (tevent_req_nomem(subreq2, req)) {
			return;
		}
		smb1cli_req_set_mid(subreq2, state->mid);

		status = smb1cli_req_chain_submit(&subreq2, 1);

		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		tevent_req_set_callback(subreq2, smb1cli_trans_done2, req);
		return;
	}

	return;

 fail:
	smb1cli_trans_cleanup_primary(state);
	tevent_req_nterror(req, status);
}

NTSTATUS smb1cli_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    uint16_t *recv_flags2,
			    uint16_t **setup, uint8_t min_setup,
			    uint8_t *num_setup,
			    uint8_t **param, uint32_t min_param,
			    uint32_t *num_param,
			    uint8_t **data, uint32_t min_data,
			    uint32_t *num_data)
{
	struct smb1cli_trans_state *state =
		tevent_req_data(req,
		struct smb1cli_trans_state);
	NTSTATUS status;

	smb1cli_trans_cleanup_primary(state);

	if (tevent_req_is_nterror(req, &status)) {
		if (!NT_STATUS_IS_ERR(status)) {
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		tevent_req_received(req);
		return status;
	}

	if ((state->num_rsetup < min_setup)
	    || (state->rparam.total < min_param)
	    || (state->rdata.total < min_data)) {
		tevent_req_received(req);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (recv_flags2 != NULL) {
		*recv_flags2 = state->recv_flags2;
	}

	if (setup != NULL) {
		*setup = talloc_move(mem_ctx, &state->rsetup);
		*num_setup = state->num_rsetup;
	} else {
		TALLOC_FREE(state->rsetup);
	}

	if (param != NULL) {
		*param = talloc_move(mem_ctx, &state->rparam.data);
		*num_param = state->rparam.total;
	} else {
		TALLOC_FREE(state->rparam.data);
	}

	if (data != NULL) {
		*data = talloc_move(mem_ctx, &state->rdata.data);
		*num_data = state->rdata.total;
	} else {
		TALLOC_FREE(state->rdata.data);
	}

	status = state->status;
	tevent_req_received(req);
	return status;
}

NTSTATUS smb1cli_trans(TALLOC_CTX *mem_ctx, struct smbXcli_conn *conn,
		uint8_t trans_cmd,
		uint8_t additional_flags, uint8_t clear_flags,
		uint16_t additional_flags2, uint16_t clear_flags2,
		uint32_t timeout_msec,
		uint32_t pid,
		struct smbXcli_tcon *tcon,
		struct smbXcli_session *session,
		const char *pipe_name, uint16_t fid, uint16_t function,
		int flags,
		uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
		uint8_t *param, uint32_t num_param, uint32_t max_param,
		uint8_t *data, uint32_t num_data, uint32_t max_data,
		uint16_t *recv_flags2,
		uint16_t **rsetup, uint8_t min_rsetup, uint8_t *num_rsetup,
		uint8_t **rparam, uint32_t min_rparam, uint32_t *num_rparam,
		uint8_t **rdata, uint32_t min_rdata, uint32_t *num_rdata)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER_MIX;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = smb1cli_trans_send(frame, ev, conn, trans_cmd,
				 additional_flags, clear_flags,
				 additional_flags2, clear_flags2,
				 timeout_msec,
				 pid, tcon, session,
				 pipe_name, fid, function, flags,
				 setup, num_setup, max_setup,
				 param, num_param, max_param,
				 data, num_data, max_data);
	if (req == NULL) {
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = smb1cli_trans_recv(req, mem_ctx, recv_flags2,
				    rsetup, min_rsetup, num_rsetup,
				    rparam, min_rparam, num_rparam,
				    rdata, min_rdata, num_rdata);
 fail:
	TALLOC_FREE(frame);
	return status;
}
