/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2010

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
#include "../lib/tsocket/tsocket.h"
#include "../lib/tsocket/tsocket_internal.h"
#include "smb_common.h"
#include "smbXcli_base.h"
#include "tstream_smbXcli_np.h"
#include "libcli/security/security.h"

static const struct tstream_context_ops tstream_smbXcli_np_ops;

#define TSTREAM_SMBXCLI_NP_DESIRED_ACCESS ( \
	SEC_STD_READ_CONTROL | \
	SEC_FILE_READ_DATA | \
	SEC_FILE_WRITE_DATA | \
	SEC_FILE_APPEND_DATA | \
	SEC_FILE_READ_EA | \
	SEC_FILE_WRITE_EA | \
	SEC_FILE_READ_ATTRIBUTE | \
	SEC_FILE_WRITE_ATTRIBUTE | \
0)

struct tstream_smbXcli_np_ref;

struct tstream_smbXcli_np {
	struct smbXcli_conn *conn;
	struct tstream_smbXcli_np_ref *conn_ref;
	struct smbXcli_session *session;
	struct tstream_smbXcli_np_ref *session_ref;
	struct smbXcli_tcon *tcon;
	struct tstream_smbXcli_np_ref *tcon_ref;
	uint16_t pid;
	unsigned int timeout;

	const char *npipe;
	bool is_smb1;
	uint16_t fnum;
	uint64_t fid_persistent;
	uint64_t fid_volatile;

	struct {
		bool active;
		struct tevent_req *read_req;
		struct tevent_req *write_req;
		uint16_t setup[2];
	} trans;

	struct {
		off_t ofs;
		size_t left;
		uint8_t *buf;
	} read, write;
};

struct tstream_smbXcli_np_ref {
	struct tstream_smbXcli_np *cli_nps;
};

static int tstream_smbXcli_np_destructor(struct tstream_smbXcli_np *cli_nps)
{
	NTSTATUS status;

	if (cli_nps->conn_ref != NULL) {
		cli_nps->conn_ref->cli_nps = NULL;
		TALLOC_FREE(cli_nps->conn_ref);
	}

	if (cli_nps->session_ref != NULL) {
		cli_nps->session_ref->cli_nps = NULL;
		TALLOC_FREE(cli_nps->session_ref);
	}

	if (cli_nps->tcon_ref != NULL) {
		cli_nps->tcon_ref->cli_nps = NULL;
		TALLOC_FREE(cli_nps->tcon_ref);
	}

	if (!smbXcli_conn_is_connected(cli_nps->conn)) {
		return 0;
	}

	/*
	 * TODO: do not use a sync call with a destructor!!!
	 *
	 * This only happens, if a caller does talloc_free(),
	 * while the everything was still ok.
	 *
	 * If we get an unexpected failure within a normal
	 * operation, we already do an async cli_close_send()/_recv().
	 *
	 * Once we've fixed all callers to call
	 * tstream_disconnect_send()/_recv(), this will
	 * never be called.
	 *
	 * We use a maximun timeout of 1 second == 1000 msec.
	 */
	cli_nps->timeout = MIN(cli_nps->timeout, 1000);

	if (cli_nps->is_smb1) {
		status = smb1cli_close(cli_nps->conn,
				       cli_nps->timeout,
				       cli_nps->pid,
				       cli_nps->tcon,
				       cli_nps->session,
				       cli_nps->fnum, UINT32_MAX);
	} else {
		status = smb2cli_close(cli_nps->conn,
				       cli_nps->timeout,
				       cli_nps->session,
				       cli_nps->tcon,
				       0, /* flags */
				       cli_nps->fid_persistent,
				       cli_nps->fid_volatile);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("tstream_smbXcli_np_destructor: cli_close "
			  "failed on pipe %s. Error was %s\n",
			  cli_nps->npipe, nt_errstr(status)));
	}
	/*
	 * We can't do much on failure
	 */
	return 0;
}

static int tstream_smbXcli_np_ref_destructor(struct tstream_smbXcli_np_ref *ref)
{
	if (ref->cli_nps == NULL) {
		return 0;
	}

	if (ref->cli_nps->conn == NULL) {
		return 0;
	}

	ref->cli_nps->conn = NULL;
	ref->cli_nps->session = NULL;
	ref->cli_nps->tcon = NULL;

	TALLOC_FREE(ref->cli_nps->conn_ref);
	TALLOC_FREE(ref->cli_nps->session_ref);
	TALLOC_FREE(ref->cli_nps->tcon_ref);

	return 0;
};

static struct tevent_req *tstream_smbXcli_np_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct tstream_context *stream);
static int tstream_smbXcli_np_disconnect_recv(struct tevent_req *req,
					      int *perrno);

struct tstream_smbXcli_np_open_state {
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint16_t pid;
	unsigned int timeout;

	bool is_smb1;
	uint16_t fnum;
	uint64_t fid_persistent;
	uint64_t fid_volatile;
	const char *npipe;
};

static void tstream_smbXcli_np_open_done(struct tevent_req *subreq);

struct tevent_req *tstream_smbXcli_np_open_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smbXcli_conn *conn,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon,
						uint16_t pid,
						unsigned int timeout,
						const char *npipe)
{
	struct tevent_req *req;
	struct tstream_smbXcli_np_open_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_smbXcli_np_open_state);
	if (!req) {
		return NULL;
	}
	state->conn = conn;
	state->tcon = tcon;
	state->session = session;
	state->pid = pid;
	state->timeout = timeout;

	state->npipe = talloc_strdup(state, npipe);
	if (tevent_req_nomem(state->npipe, req)) {
		return tevent_req_post(req, ev);
	}

	if (smbXcli_conn_protocol(conn) < PROTOCOL_SMB2_02) {
		state->is_smb1 = true;
	}

	if (state->is_smb1) {
		const char *smb1_npipe;

		/*
		 * Windows and newer Samba versions allow
		 * the pipe name without leading backslash,
		 * but we should better behave like windows clients
		 */
		smb1_npipe = talloc_asprintf(state, "\\%s", state->npipe);
		if (tevent_req_nomem(smb1_npipe, req)) {
			return tevent_req_post(req, ev);
		}
		subreq = smb1cli_ntcreatex_send(state, ev, state->conn,
						state->timeout,
						state->pid,
						state->tcon,
						state->session,
						smb1_npipe,
						0, /* CreatFlags */
						0, /* RootDirectoryFid */
						TSTREAM_SMBXCLI_NP_DESIRED_ACCESS,
						0, /* AllocationSize */
						0, /* FileAttributes */
						FILE_SHARE_READ|FILE_SHARE_WRITE,
						FILE_OPEN, /* CreateDisposition */
						0, /* CreateOptions */
						2, /* NTCREATEX_IMPERSONATION_IMPERSONATION */
						0); /* SecurityFlags */
	} else {
		subreq = smb2cli_create_send(state, ev, state->conn,
					     state->timeout, state->session,
					     state->tcon,
					     npipe,
					     SMB2_OPLOCK_LEVEL_NONE,
					     SMB2_IMPERSONATION_IMPERSONATION,
					     TSTREAM_SMBXCLI_NP_DESIRED_ACCESS,
					     0, /* file_attributes */
					     FILE_SHARE_READ|FILE_SHARE_WRITE,
					     FILE_OPEN,
					     0, /* create_options */
					     NULL); /* blobs */
	}
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tstream_smbXcli_np_open_done, req);

	return req;
}

static void tstream_smbXcli_np_open_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct tstream_smbXcli_np_open_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_open_state);
	NTSTATUS status;

	if (state->is_smb1) {
		status = smb1cli_ntcreatex_recv(subreq, &state->fnum);
	} else {
		status = smb2cli_create_recv(subreq,
					     &state->fid_persistent,
					     &state->fid_volatile,
					     NULL, NULL, NULL);
	}
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS _tstream_smbXcli_np_open_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       struct tstream_context **_stream,
				       const char *location)
{
	struct tstream_smbXcli_np_open_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_open_state);
	struct tstream_context *stream;
	struct tstream_smbXcli_np *cli_nps;
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	stream = tstream_context_create(mem_ctx,
					&tstream_smbXcli_np_ops,
					&cli_nps,
					struct tstream_smbXcli_np,
					location);
	if (!stream) {
		tevent_req_received(req);
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(cli_nps);

	cli_nps->conn_ref = talloc_zero(state->conn,
					struct tstream_smbXcli_np_ref);
	if (cli_nps->conn_ref == NULL) {
		TALLOC_FREE(cli_nps);
		tevent_req_received(req);
		return NT_STATUS_NO_MEMORY;
	}
	cli_nps->conn_ref->cli_nps = cli_nps;

	cli_nps->session_ref = talloc_zero(state->session,
					struct tstream_smbXcli_np_ref);
	if (cli_nps->session_ref == NULL) {
		TALLOC_FREE(cli_nps);
		tevent_req_received(req);
		return NT_STATUS_NO_MEMORY;
	}
	cli_nps->session_ref->cli_nps = cli_nps;

	cli_nps->tcon_ref = talloc_zero(state->tcon,
					struct tstream_smbXcli_np_ref);
	if (cli_nps->tcon_ref == NULL) {
		TALLOC_FREE(cli_nps);
		tevent_req_received(req);
		return NT_STATUS_NO_MEMORY;
	}
	cli_nps->tcon_ref->cli_nps = cli_nps;

	cli_nps->conn = state->conn;
	cli_nps->session = state->session;
	cli_nps->tcon = state->tcon;
	cli_nps->pid  = state->pid;
	cli_nps->timeout = state->timeout;
	cli_nps->npipe = talloc_move(cli_nps, &state->npipe);
	cli_nps->is_smb1 = state->is_smb1;
	cli_nps->fnum = state->fnum;
	cli_nps->fid_persistent = state->fid_persistent;
	cli_nps->fid_volatile = state->fid_volatile;

	talloc_set_destructor(cli_nps, tstream_smbXcli_np_destructor);
	talloc_set_destructor(cli_nps->conn_ref,
			      tstream_smbXcli_np_ref_destructor);
	talloc_set_destructor(cli_nps->session_ref,
			      tstream_smbXcli_np_ref_destructor);
	talloc_set_destructor(cli_nps->tcon_ref,
			      tstream_smbXcli_np_ref_destructor);

	cli_nps->trans.active = false;
	cli_nps->trans.read_req = NULL;
	cli_nps->trans.write_req = NULL;
	SSVAL(cli_nps->trans.setup+0, 0, TRANSACT_DCERPCCMD);
	SSVAL(cli_nps->trans.setup+1, 0, cli_nps->fnum);

	*_stream = stream;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

static ssize_t tstream_smbXcli_np_pending_bytes(struct tstream_context *stream)
{
	struct tstream_smbXcli_np *cli_nps = tstream_context_data(stream,
					 struct tstream_smbXcli_np);

	if (!smbXcli_conn_is_connected(cli_nps->conn)) {
		errno = ENOTCONN;
		return -1;
	}

	return cli_nps->read.left;
}

bool tstream_is_smbXcli_np(struct tstream_context *stream)
{
	struct tstream_smbXcli_np *cli_nps =
		talloc_get_type(_tstream_context_data(stream),
		struct tstream_smbXcli_np);

	if (!cli_nps) {
		return false;
	}

	return true;
}

NTSTATUS tstream_smbXcli_np_use_trans(struct tstream_context *stream)
{
	struct tstream_smbXcli_np *cli_nps = tstream_context_data(stream,
					 struct tstream_smbXcli_np);

	if (cli_nps->trans.read_req) {
		return NT_STATUS_PIPE_BUSY;
	}

	if (cli_nps->trans.write_req) {
		return NT_STATUS_PIPE_BUSY;
	}

	if (cli_nps->trans.active) {
		return NT_STATUS_PIPE_BUSY;
	}

	cli_nps->trans.active = true;

	return NT_STATUS_OK;
}

unsigned int tstream_smbXcli_np_set_timeout(struct tstream_context *stream,
					    unsigned int timeout)
{
	struct tstream_smbXcli_np *cli_nps = tstream_context_data(stream,
					 struct tstream_smbXcli_np);
	unsigned int old_timeout = cli_nps->timeout;

	cli_nps->timeout = timeout;
	return old_timeout;
}

struct tstream_smbXcli_np_writev_state {
	struct tstream_context *stream;
	struct tevent_context *ev;

	struct iovec *vector;
	size_t count;

	int ret;

	struct {
		int val;
		const char *location;
	} error;
};

static int tstream_smbXcli_np_writev_state_destructor(struct tstream_smbXcli_np_writev_state *state)
{
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);

	cli_nps->trans.write_req = NULL;

	return 0;
}

static void tstream_smbXcli_np_writev_write_next(struct tevent_req *req);

static struct tevent_req *tstream_smbXcli_np_writev_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					const struct iovec *vector,
					size_t count)
{
	struct tevent_req *req;
	struct tstream_smbXcli_np_writev_state *state;
	struct tstream_smbXcli_np *cli_nps = tstream_context_data(stream,
					 struct tstream_smbXcli_np);

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_smbXcli_np_writev_state);
	if (!req) {
		return NULL;
	}
	state->stream = stream;
	state->ev = ev;
	state->ret = 0;

	talloc_set_destructor(state, tstream_smbXcli_np_writev_state_destructor);

	if (!smbXcli_conn_is_connected(cli_nps->conn)) {
		tevent_req_error(req, ENOTCONN);
		return tevent_req_post(req, ev);
	}

	/*
	 * we make a copy of the vector so we can change the structure
	 */
	state->vector = talloc_array(state, struct iovec, count);
	if (tevent_req_nomem(state->vector, req)) {
		return tevent_req_post(req, ev);
	}
	memcpy(state->vector, vector, sizeof(struct iovec) * count);
	state->count = count;

	tstream_smbXcli_np_writev_write_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_smbXcli_np_readv_trans_start(struct tevent_req *req);
static void tstream_smbXcli_np_writev_write_done(struct tevent_req *subreq);

static void tstream_smbXcli_np_writev_write_next(struct tevent_req *req)
{
	struct tstream_smbXcli_np_writev_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_writev_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);
	struct tevent_req *subreq;
	size_t i;
	size_t left = 0;

	for (i=0; i < state->count; i++) {
		left += state->vector[i].iov_len;
	}

	if (left == 0) {
		TALLOC_FREE(cli_nps->write.buf);
		tevent_req_done(req);
		return;
	}

	cli_nps->write.ofs = 0;
	cli_nps->write.left = MIN(left, TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE);
	cli_nps->write.buf = talloc_realloc(cli_nps, cli_nps->write.buf,
					    uint8_t, cli_nps->write.left);
	if (tevent_req_nomem(cli_nps->write.buf, req)) {
		return;
	}

	/*
	 * copy the pending buffer first
	 */
	while (cli_nps->write.left > 0 && state->count > 0) {
		uint8_t *base = (uint8_t *)state->vector[0].iov_base;
		size_t len = MIN(cli_nps->write.left, state->vector[0].iov_len);

		memcpy(cli_nps->write.buf + cli_nps->write.ofs, base, len);

		base += len;
		state->vector[0].iov_base = base;
		state->vector[0].iov_len -= len;

		cli_nps->write.ofs += len;
		cli_nps->write.left -= len;

		if (state->vector[0].iov_len == 0) {
			state->vector += 1;
			state->count -= 1;
		}

		state->ret += len;
	}

	if (cli_nps->trans.active && state->count == 0) {
		cli_nps->trans.active = false;
		cli_nps->trans.write_req = req;
		return;
	}

	if (cli_nps->trans.read_req && state->count == 0) {
		cli_nps->trans.write_req = req;
		tstream_smbXcli_np_readv_trans_start(cli_nps->trans.read_req);
		return;
	}

	if (cli_nps->is_smb1) {
		subreq = smb1cli_writex_send(state, state->ev,
					     cli_nps->conn,
					     cli_nps->timeout,
					     cli_nps->pid,
					     cli_nps->tcon,
					     cli_nps->session,
					     cli_nps->fnum,
					     8, /* 8 means message mode. */
					     cli_nps->write.buf,
					     0, /* offset */
					     cli_nps->write.ofs); /* size */
	} else {
		subreq = smb2cli_write_send(state, state->ev,
					    cli_nps->conn,
					    cli_nps->timeout,
					    cli_nps->session,
					    cli_nps->tcon,
					    cli_nps->write.ofs, /* length */
					    0, /* offset */
					    cli_nps->fid_persistent,
					    cli_nps->fid_volatile,
					    0, /* remaining_bytes */
					    0, /* flags */
					    cli_nps->write.buf);
	}
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				tstream_smbXcli_np_writev_write_done,
				req);
}

static void tstream_smbXcli_np_writev_disconnect_now(struct tevent_req *req,
						 int error,
						 const char *location);

static void tstream_smbXcli_np_writev_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct tstream_smbXcli_np_writev_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_writev_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);
	uint32_t written;
	NTSTATUS status;

	if (cli_nps->is_smb1) {
		status = smb1cli_writex_recv(subreq, &written, NULL);
	} else {
		status = smb2cli_write_recv(subreq, &written);
	}
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tstream_smbXcli_np_writev_disconnect_now(req, EPIPE, __location__);
		return;
	}

	if (written != cli_nps->write.ofs) {
		tstream_smbXcli_np_writev_disconnect_now(req, EIO, __location__);
		return;
	}

	tstream_smbXcli_np_writev_write_next(req);
}

static void tstream_smbXcli_np_writev_disconnect_done(struct tevent_req *subreq);

static void tstream_smbXcli_np_writev_disconnect_now(struct tevent_req *req,
						 int error,
						 const char *location)
{
	struct tstream_smbXcli_np_writev_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_writev_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);
	struct tevent_req *subreq;

	state->error.val = error;
	state->error.location = location;

	if (!smbXcli_conn_is_connected(cli_nps->conn)) {
		/* return the original error */
		_tevent_req_error(req, state->error.val, state->error.location);
		return;
	}

	subreq = tstream_smbXcli_np_disconnect_send(state, state->ev,
						    state->stream);
	if (subreq == NULL) {
		/* return the original error */
		_tevent_req_error(req, state->error.val, state->error.location);
		return;
	}
	tevent_req_set_callback(subreq,
				tstream_smbXcli_np_writev_disconnect_done,
				req);
}

static void tstream_smbXcli_np_writev_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct tstream_smbXcli_np_writev_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_writev_state);
	int error;

	tstream_smbXcli_np_disconnect_recv(subreq, &error);
	TALLOC_FREE(subreq);

	/* return the original error */
	_tevent_req_error(req, state->error.val, state->error.location);
}

static int tstream_smbXcli_np_writev_recv(struct tevent_req *req,
				      int *perrno)
{
	struct tstream_smbXcli_np_writev_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_writev_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_smbXcli_np_readv_state {
	struct tstream_context *stream;
	struct tevent_context *ev;

	struct iovec *vector;
	size_t count;

	int ret;

	struct {
		struct tevent_immediate *im;
	} trans;

	struct {
		int val;
		const char *location;
	} error;
};

static int tstream_smbXcli_np_readv_state_destructor(struct tstream_smbXcli_np_readv_state *state)
{
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);

	cli_nps->trans.read_req = NULL;

	return 0;
}

static void tstream_smbXcli_np_readv_read_next(struct tevent_req *req);

static struct tevent_req *tstream_smbXcli_np_readv_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					struct iovec *vector,
					size_t count)
{
	struct tevent_req *req;
	struct tstream_smbXcli_np_readv_state *state;
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(stream, struct tstream_smbXcli_np);

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_smbXcli_np_readv_state);
	if (!req) {
		return NULL;
	}
	state->stream = stream;
	state->ev = ev;
	state->ret = 0;

	talloc_set_destructor(state, tstream_smbXcli_np_readv_state_destructor);

	if (!smbXcli_conn_is_connected(cli_nps->conn)) {
		tevent_req_error(req, ENOTCONN);
		return tevent_req_post(req, ev);
	}

	/*
	 * we make a copy of the vector so we can change the structure
	 */
	state->vector = talloc_array(state, struct iovec, count);
	if (tevent_req_nomem(state->vector, req)) {
		return tevent_req_post(req, ev);
	}
	memcpy(state->vector, vector, sizeof(struct iovec) * count);
	state->count = count;

	tstream_smbXcli_np_readv_read_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_smbXcli_np_readv_read_done(struct tevent_req *subreq);

static void tstream_smbXcli_np_readv_read_next(struct tevent_req *req)
{
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_readv_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);
	struct tevent_req *subreq;

	/*
	 * copy the pending buffer first
	 */
	while (cli_nps->read.left > 0 && state->count > 0) {
		uint8_t *base = (uint8_t *)state->vector[0].iov_base;
		size_t len = MIN(cli_nps->read.left, state->vector[0].iov_len);

		memcpy(base, cli_nps->read.buf + cli_nps->read.ofs, len);

		base += len;
		state->vector[0].iov_base = base;
		state->vector[0].iov_len -= len;

		cli_nps->read.ofs += len;
		cli_nps->read.left -= len;

		if (state->vector[0].iov_len == 0) {
			state->vector += 1;
			state->count -= 1;
		}

		state->ret += len;
	}

	if (cli_nps->read.left == 0) {
		TALLOC_FREE(cli_nps->read.buf);
	}

	if (state->count == 0) {
		tevent_req_done(req);
		return;
	}

	if (cli_nps->trans.active) {
		cli_nps->trans.active = false;
		cli_nps->trans.read_req = req;
		return;
	}

	if (cli_nps->trans.write_req) {
		cli_nps->trans.read_req = req;
		tstream_smbXcli_np_readv_trans_start(req);
		return;
	}

	if (cli_nps->is_smb1) {
		subreq = smb1cli_readx_send(state, state->ev,
					    cli_nps->conn,
					    cli_nps->timeout,
					    cli_nps->pid,
					    cli_nps->tcon,
					    cli_nps->session,
					    cli_nps->fnum,
					    0, /* offset */
					    TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE);
	} else {
		subreq = smb2cli_read_send(state, state->ev,
					   cli_nps->conn,
					   cli_nps->timeout,
					   cli_nps->session,
					   cli_nps->tcon,
					   TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE, /* length */
					   0, /* offset */
					   cli_nps->fid_persistent,
					   cli_nps->fid_volatile,
					   0, /* minimum_count */
					   0); /* remaining_bytes */
	}
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				tstream_smbXcli_np_readv_read_done,
				req);
}

static void tstream_smbXcli_np_readv_trans_done(struct tevent_req *subreq);

static void tstream_smbXcli_np_readv_trans_start(struct tevent_req *req)
{
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_readv_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);
	struct tevent_req *subreq;

	state->trans.im = tevent_create_immediate(state);
	if (tevent_req_nomem(state->trans.im, req)) {
		return;
	}

	if (cli_nps->is_smb1) {
		subreq = smb1cli_trans_send(state, state->ev,
					    cli_nps->conn, SMBtrans,
					    0, 0, /* *_flags */
					    0, 0, /* *_flags2 */
					    cli_nps->timeout,
					    cli_nps->pid,
					    cli_nps->tcon,
					    cli_nps->session,
					    "\\PIPE\\",
					    0, 0, 0,
					    cli_nps->trans.setup, 2,
					    0,
					    NULL, 0, 0,
					    cli_nps->write.buf,
					    cli_nps->write.ofs,
					    TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE);
	} else {
		DATA_BLOB in_input_buffer = data_blob_null;
		DATA_BLOB in_output_buffer = data_blob_null;

		in_input_buffer = data_blob_const(cli_nps->write.buf,
						  cli_nps->write.ofs);

		subreq = smb2cli_ioctl_send(state, state->ev,
					    cli_nps->conn,
					    cli_nps->timeout,
					    cli_nps->session,
					    cli_nps->tcon,
					    cli_nps->fid_persistent,
					    cli_nps->fid_volatile,
					    FSCTL_NAMED_PIPE_READ_WRITE,
					    0, /* in_max_input_length */
					    &in_input_buffer,
					    /* in_max_output_length */
					    TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE,
					    &in_output_buffer,
					    SMB2_IOCTL_FLAG_IS_FSCTL);
	}
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				tstream_smbXcli_np_readv_trans_done,
				req);
}

static void tstream_smbXcli_np_readv_disconnect_now(struct tevent_req *req,
						int error,
						const char *location);
static void tstream_smbXcli_np_readv_trans_next(struct tevent_context *ctx,
						struct tevent_immediate *im,
						void *private_data);

static void tstream_smbXcli_np_readv_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_readv_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream, struct tstream_smbXcli_np);
	uint8_t *rcvbuf;
	uint32_t received;
	NTSTATUS status;

	if (cli_nps->is_smb1) {
		status = smb1cli_trans_recv(subreq, state, NULL, NULL, 0, NULL,
					    NULL, 0, NULL,
					    &rcvbuf, 0, &received);
	} else {
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;

		status = smb2cli_ioctl_recv(subreq, state,
					    &out_input_buffer,
					    &out_output_buffer);

		/* Note that rcvbuf is not a talloc pointer here */
		rcvbuf = out_output_buffer.data;
		received = out_output_buffer.length;
	}
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		/*
		 * STATUS_BUFFER_OVERFLOW means that there's
		 * more data to read when the named pipe is used
		 * in message mode (which is the case here).
		 *
		 * But we hide this from the caller.
		 */
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		tstream_smbXcli_np_readv_disconnect_now(req, EPIPE, __location__);
		return;
	}

	if (received > TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE) {
		tstream_smbXcli_np_readv_disconnect_now(req, EIO, __location__);
		return;
	}

	if (received == 0) {
		tstream_smbXcli_np_readv_disconnect_now(req, EPIPE, __location__);
		return;
	}

	cli_nps->read.ofs = 0;
	cli_nps->read.left = received;
	cli_nps->read.buf = talloc_array(cli_nps, uint8_t, received);
	if (cli_nps->read.buf == NULL) {
		TALLOC_FREE(subreq);
		tevent_req_nomem(cli_nps->read.buf, req);
		return;
	}
	memcpy(cli_nps->read.buf, rcvbuf, received);

	if (cli_nps->trans.write_req == NULL) {
		tstream_smbXcli_np_readv_read_next(req);
		return;
	}

	tevent_schedule_immediate(state->trans.im, state->ev,
				  tstream_smbXcli_np_readv_trans_next, req);

	tevent_req_done(cli_nps->trans.write_req);
}

static void tstream_smbXcli_np_readv_trans_next(struct tevent_context *ctx,
					    struct tevent_immediate *im,
					    void *private_data)
{
	struct tevent_req *req =
		talloc_get_type_abort(private_data,
		struct tevent_req);

	tstream_smbXcli_np_readv_read_next(req);
}

static void tstream_smbXcli_np_readv_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_readv_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream, struct tstream_smbXcli_np);
	uint8_t *rcvbuf;
	uint32_t received;
	NTSTATUS status;

	/*
	 * We must free subreq in this function as there is
	 * a timer event attached to it.
	 */

	if (cli_nps->is_smb1) {
		status = smb1cli_readx_recv(subreq, &received, &rcvbuf);
	} else {
		status = smb2cli_read_recv(subreq, state, &rcvbuf, &received);
	}
	/*
	 * We can't TALLOC_FREE(subreq) as usual here, as rcvbuf still is a
	 * child of that.
	 */
	if (NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		/*
		 * STATUS_BUFFER_OVERFLOW means that there's
		 * more data to read when the named pipe is used
		 * in message mode (which is the case here).
		 *
		 * But we hide this from the caller.
		 */
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		tstream_smbXcli_np_readv_disconnect_now(req, EPIPE, __location__);
		return;
	}

	if (received > TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE) {
		TALLOC_FREE(subreq);
		tstream_smbXcli_np_readv_disconnect_now(req, EIO, __location__);
		return;
	}

	if (received == 0) {
		TALLOC_FREE(subreq);
		tstream_smbXcli_np_readv_disconnect_now(req, EPIPE, __location__);
		return;
	}

	cli_nps->read.ofs = 0;
	cli_nps->read.left = received;
	cli_nps->read.buf = talloc_array(cli_nps, uint8_t, received);
	if (cli_nps->read.buf == NULL) {
		TALLOC_FREE(subreq);
		tevent_req_nomem(cli_nps->read.buf, req);
		return;
	}
	memcpy(cli_nps->read.buf, rcvbuf, received);
	TALLOC_FREE(subreq);

	tstream_smbXcli_np_readv_read_next(req);
}

static void tstream_smbXcli_np_readv_disconnect_done(struct tevent_req *subreq);

static void tstream_smbXcli_np_readv_error(struct tevent_req *req);

static void tstream_smbXcli_np_readv_disconnect_now(struct tevent_req *req,
						int error,
						const char *location)
{
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_readv_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);
	struct tevent_req *subreq;

	state->error.val = error;
	state->error.location = location;

	if (!smbXcli_conn_is_connected(cli_nps->conn)) {
		/* return the original error */
		tstream_smbXcli_np_readv_error(req);
		return;
	}

	subreq = tstream_smbXcli_np_disconnect_send(state, state->ev,
						    state->stream);
	if (subreq == NULL) {
		/* return the original error */
		tstream_smbXcli_np_readv_error(req);
		return;
	}
	tevent_req_set_callback(subreq,
				tstream_smbXcli_np_readv_disconnect_done,
				req);
}

static void tstream_smbXcli_np_readv_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	int error;

	tstream_smbXcli_np_disconnect_recv(subreq, &error);
	TALLOC_FREE(subreq);

	tstream_smbXcli_np_readv_error(req);
}

static void tstream_smbXcli_np_readv_error_trigger(struct tevent_context *ctx,
						   struct tevent_immediate *im,
						   void *private_data);

static void tstream_smbXcli_np_readv_error(struct tevent_req *req)
{
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_readv_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream,
		struct tstream_smbXcli_np);

	if (cli_nps->trans.write_req == NULL) {
		/* return the original error */
		_tevent_req_error(req, state->error.val, state->error.location);
		return;
	}

	if (state->trans.im == NULL) {
		/* return the original error */
		_tevent_req_error(req, state->error.val, state->error.location);
		return;
	}

	tevent_schedule_immediate(state->trans.im, state->ev,
				  tstream_smbXcli_np_readv_error_trigger, req);

	/* return the original error for writev */
	_tevent_req_error(cli_nps->trans.write_req,
			  state->error.val, state->error.location);
}

static void tstream_smbXcli_np_readv_error_trigger(struct tevent_context *ctx,
						   struct tevent_immediate *im,
						   void *private_data)
{
	struct tevent_req *req =
		talloc_get_type_abort(private_data,
		struct tevent_req);
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req,
		struct tstream_smbXcli_np_readv_state);

	/* return the original error */
	_tevent_req_error(req, state->error.val, state->error.location);
}

static int tstream_smbXcli_np_readv_recv(struct tevent_req *req,
					 int *perrno)
{
	struct tstream_smbXcli_np_readv_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_readv_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_smbXcli_np_disconnect_state {
	struct tstream_context *stream;
	struct tevent_req *subreq;
};

static void tstream_smbXcli_np_disconnect_done(struct tevent_req *subreq);
static void tstream_smbXcli_np_disconnect_cleanup(struct tevent_req *req,
					enum tevent_req_state req_state);

static struct tevent_req *tstream_smbXcli_np_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct tstream_context *stream)
{
	struct tstream_smbXcli_np *cli_nps = tstream_context_data(stream,
					 struct tstream_smbXcli_np);
	struct tevent_req *req;
	struct tstream_smbXcli_np_disconnect_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_smbXcli_np_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	state->stream = stream;

	if (!smbXcli_conn_is_connected(cli_nps->conn)) {
		tevent_req_error(req, ENOTCONN);
		return tevent_req_post(req, ev);
	}

	if (cli_nps->is_smb1) {
		subreq = smb1cli_close_send(state, ev, cli_nps->conn,
					    cli_nps->timeout,
					    cli_nps->pid,
					    cli_nps->tcon,
					    cli_nps->session,
					    cli_nps->fnum, UINT32_MAX);
	} else {
		subreq = smb2cli_close_send(state, ev, cli_nps->conn,
					    cli_nps->timeout,
					    cli_nps->session,
					    cli_nps->tcon,
					    0, /* flags */
					    cli_nps->fid_persistent,
					    cli_nps->fid_volatile);
	}
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tstream_smbXcli_np_disconnect_done, req);
	state->subreq = subreq;

	tevent_req_set_cleanup_fn(req, tstream_smbXcli_np_disconnect_cleanup);

	/*
	 * Make sure we don't send any requests anymore.
	 */
	cli_nps->conn = NULL;

	return req;
}

static void tstream_smbXcli_np_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct tstream_smbXcli_np_disconnect_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_disconnect_state);
	struct tstream_smbXcli_np *cli_nps =
		tstream_context_data(state->stream, struct tstream_smbXcli_np);
	NTSTATUS status;

	state->subreq = NULL;

	if (cli_nps->is_smb1) {
		status = smb1cli_close_recv(subreq);
	} else {
		status = smb2cli_close_recv(subreq);
	}
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_error(req, EPIPE);
		return;
	}

	cli_nps->conn = NULL;
	cli_nps->session = NULL;
	cli_nps->tcon = NULL;

	tevent_req_done(req);
}

static void tstream_smbXcli_np_disconnect_free(struct tevent_req *subreq);

static void tstream_smbXcli_np_disconnect_cleanup(struct tevent_req *req,
					enum tevent_req_state req_state)
{
	struct tstream_smbXcli_np_disconnect_state *state =
		tevent_req_data(req, struct tstream_smbXcli_np_disconnect_state);
	struct tstream_smbXcli_np *cli_nps = NULL;

	if (state->subreq == NULL) {
		return;
	}

	cli_nps = tstream_context_data(state->stream, struct tstream_smbXcli_np);

	if (cli_nps->tcon == NULL) {
		return;
	}

	/*
	 * We're no longer interested in the result
	 * any more, but need to make sure that the close
	 * request arrives at the server if the smb connection,
	 * session and tcon are still alive.
	 *
	 * We move the low level request to the tcon,
	 * which means that it stays as long as the tcon
	 * is available.
	 */
	talloc_steal(cli_nps->tcon, state->subreq);
	tevent_req_set_callback(state->subreq,
				tstream_smbXcli_np_disconnect_free,
				NULL);
	state->subreq = NULL;

	cli_nps->conn = NULL;
	cli_nps->session = NULL;
	cli_nps->tcon = NULL;
}

static void tstream_smbXcli_np_disconnect_free(struct tevent_req *subreq)
{
	TALLOC_FREE(subreq);
}

static int tstream_smbXcli_np_disconnect_recv(struct tevent_req *req,
					      int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);

	tevent_req_received(req);
	return ret;
}

static const struct tstream_context_ops tstream_smbXcli_np_ops = {
	.name			= "smbXcli_np",

	.pending_bytes		= tstream_smbXcli_np_pending_bytes,

	.readv_send		= tstream_smbXcli_np_readv_send,
	.readv_recv		= tstream_smbXcli_np_readv_recv,

	.writev_send		= tstream_smbXcli_np_writev_send,
	.writev_recv		= tstream_smbXcli_np_writev_recv,

	.disconnect_send	= tstream_smbXcli_np_disconnect_send,
	.disconnect_recv	= tstream_smbXcli_np_disconnect_recv,
};
