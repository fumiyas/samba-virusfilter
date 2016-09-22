/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Largely re-written : 2005
 *  Copyright (C) Jeremy Allison		1998 - 2005
 *  Copyright (C) Simo Sorce			2010
 *  Copyright (C) Andrew Bartlett		2011
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_server/srv_pipe_internal.h"
#include "rpc_dce.h"
#include "../libcli/named_pipe_auth/npa_tstream.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "librpc/gen_ndr/netlogon.h"
#include "librpc/gen_ndr/auth.h"
#include "../auth/auth_sam_reply.h"
#include "auth.h"
#include "rpc_server/rpc_pipes.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "rpc_contexts.h"
#include "rpc_server/rpc_config.h"
#include "librpc/ndr/ndr_table.h"
#include "rpc_server/rpc_server.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static struct npa_state *npa_state_init(TALLOC_CTX *mem_ctx)
{
	struct npa_state *npa;

	npa = talloc_zero(mem_ctx, struct npa_state);
	if (npa == NULL) {
		return NULL;
	}

	npa->read_queue = tevent_queue_create(npa, "npa_cli_read");
	if (npa->read_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	npa->write_queue = tevent_queue_create(npa, "npa_cli_write");
	if (npa->write_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	return npa;
fail:
	talloc_free(npa);
	return NULL;
}

NTSTATUS make_internal_rpc_pipe_socketpair(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev_ctx,
					   struct messaging_context *msg_ctx,
					   const char *pipe_name,
					   const struct ndr_syntax_id *syntax,
					   const struct tsocket_address *remote_address,
					   const struct auth_session_info *session_info,
					   struct npa_state **pnpa)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct named_pipe_client *npc;
	struct tevent_req *subreq;
	struct npa_state *npa;
	NTSTATUS status;
	int error;
	int rc;

	DEBUG(4, ("Create of internal pipe %s requested\n", pipe_name));

	npa = npa_state_init(tmp_ctx);
	if (npa == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	npa->file_type = FILE_TYPE_MESSAGE_MODE_PIPE;
	npa->device_state = 0xff | 0x0400 | 0x0100;
	npa->allocation_size = 4096;

	npc = named_pipe_client_init(npa,
				     ev_ctx,
				     msg_ctx,
				     pipe_name,
				     NULL, /* term_fn */
				     npa->file_type,
				     npa->device_state,
				     npa->allocation_size,
				     NULL); /* private_data */
	if (npc == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	npa->private_data = (void*) npc;

	rc = tstream_npa_socketpair(npa->file_type,
				    npa,
				    &npa->stream,
				    npc,
				    &npc->tstream);
	if (rc == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	npc->client = tsocket_address_copy(remote_address, npc);
	if (npc->client == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	npc->client_name = tsocket_address_inet_addr_string(npc->client, npc);
	if (npc->client_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	npc->session_info = copy_session_info(npc, session_info);
	if (npc->session_info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	rc = make_server_pipes_struct(npc,
				      npc->msg_ctx,
				      npc->pipe_name,
				      NCACN_NP,
				      npc->server,
				      npc->client,
				      npc->session_info,
				      &npc->p,
				      &error);
	if (rc == -1) {
		status = map_nt_error_from_unix(error);
		goto out;
	}

	npc->write_queue = tevent_queue_create(npc, "npa_server_write_queue");
	if (npc->write_queue == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	subreq = dcerpc_read_ncacn_packet_send(npc, npc->ev, npc->tstream);
	if (subreq == NULL) {
		DEBUG(2, ("Failed to start receving packets\n"));
		status = NT_STATUS_PIPE_BROKEN;
		goto out;
	}
	tevent_req_set_callback(subreq, named_pipe_packet_process, npc);

	*pnpa = talloc_steal(mem_ctx, npa);
	status = NT_STATUS_OK;
out:
	talloc_free(tmp_ctx);
	return status;
}

/****************************************************************************
 Make an internal namedpipes structure
****************************************************************************/

struct pipes_struct *make_internal_rpc_pipe_p(TALLOC_CTX *mem_ctx,
					      const struct ndr_syntax_id *syntax,
					      const struct tsocket_address *remote_address,
					      const struct auth_session_info *session_info,
					      struct messaging_context *msg_ctx)
{
	struct pipes_struct *p;
	struct pipe_rpc_fns *context_fns;
	const char *pipe_name;
	int ret;
	const struct ndr_interface_table *table;

	table = ndr_table_by_uuid(&syntax->uuid);
	if (table == NULL) {
		DEBUG(0,("unknown interface\n"));
		return NULL;
	}

	pipe_name = dcerpc_default_transport_endpoint(mem_ctx, NCACN_NP, table);

	DEBUG(4,("Create pipe requested %s\n", pipe_name));

	ret = make_base_pipes_struct(mem_ctx, msg_ctx, pipe_name,
				     NCALRPC, RPC_LITTLE_ENDIAN,
				     remote_address, NULL, &p);
	if (ret) {
		DEBUG(0,("ERROR! no memory for pipes_struct!\n"));
		return NULL;
	}

	if (!init_pipe_handles(p, syntax)) {
		DEBUG(0,("open_rpc_pipe_p: init_pipe_handles failed.\n"));
		TALLOC_FREE(p);
		return NULL;
	}

	p->session_info = copy_session_info(p, session_info);
	if (p->session_info == NULL) {
		DEBUG(0, ("open_rpc_pipe_p: copy_serverinfo failed\n"));
		close_policy_by_pipe(p);
		TALLOC_FREE(p);
		return NULL;
	}

	context_fns = talloc_zero(p, struct pipe_rpc_fns);
	if (context_fns == NULL) {
		DEBUG(0,("talloc() failed!\n"));
		TALLOC_FREE(p);
		return NULL;
	}

	context_fns->next = context_fns->prev = NULL;
	context_fns->n_cmds = rpc_srv_get_pipe_num_cmds(syntax);
	context_fns->cmds = rpc_srv_get_pipe_cmds(syntax);
	context_fns->context_id = 0;
	context_fns->syntax = *syntax;

	/* add to the list of open contexts */
	DLIST_ADD(p->contexts, context_fns);

	DEBUG(4,("Created internal pipe %s\n", pipe_name));

	return p;
}

static NTSTATUS rpcint_dispatch(struct pipes_struct *p,
				TALLOC_CTX *mem_ctx,
				uint32_t opnum,
				const DATA_BLOB *in_data,
				DATA_BLOB *out_data)
{
	struct pipe_rpc_fns *fns = find_pipe_fns_by_context(p->contexts, 0);
	uint32_t num_cmds = fns->n_cmds;
	const struct api_struct *cmds = fns->cmds;
	uint32_t i;
	bool ok;

	/* set opnum */
	p->opnum = opnum;

	for (i = 0; i < num_cmds; i++) {
		if (cmds[i].opnum == opnum && cmds[i].fn != NULL) {
			break;
		}
	}

	if (i == num_cmds) {
		return NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE;
	}

	p->in_data.data = *in_data;
	p->out_data.rdata = data_blob_null;

	ok = cmds[i].fn(p);
	p->in_data.data = data_blob_null;
	if (!ok) {
		data_blob_free(&p->out_data.rdata);
		talloc_free_children(p->mem_ctx);
		return NT_STATUS_RPC_CALL_FAILED;
	}

	if (p->fault_state) {
		NTSTATUS status;

		status = NT_STATUS(p->fault_state);
		p->fault_state = 0;
		data_blob_free(&p->out_data.rdata);
		talloc_free_children(p->mem_ctx);
		return status;
	}

	*out_data = p->out_data.rdata;
	talloc_steal(mem_ctx, out_data->data);
	p->out_data.rdata = data_blob_null;

	talloc_free_children(p->mem_ctx);
	return NT_STATUS_OK;
}

struct rpcint_bh_state {
	struct pipes_struct *p;
};

static bool rpcint_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct rpcint_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpcint_bh_state);

	if (!hs->p) {
		return false;
	}

	return true;
}

static uint32_t rpcint_bh_set_timeout(struct dcerpc_binding_handle *h,
				      uint32_t timeout)
{
	/* TODO: implement timeouts */
	return UINT32_MAX;
}

struct rpcint_bh_raw_call_state {
	DATA_BLOB in_data;
	DATA_BLOB out_data;
	uint32_t out_flags;
};

static struct tevent_req *rpcint_bh_raw_call_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct dcerpc_binding_handle *h,
						  const struct GUID *object,
						  uint32_t opnum,
						  uint32_t in_flags,
						  const uint8_t *in_data,
						  size_t in_length)
{
	struct rpcint_bh_state *hs =
		dcerpc_binding_handle_data(h,
		struct rpcint_bh_state);
	struct tevent_req *req;
	struct rpcint_bh_raw_call_state *state;
	bool ok;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct rpcint_bh_raw_call_state);
	if (req == NULL) {
		return NULL;
	}
	state->in_data.data = discard_const_p(uint8_t, in_data);
	state->in_data.length = in_length;

	ok = rpcint_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	/* TODO: allow async */
	status = rpcint_dispatch(hs->p, state, opnum,
				 &state->in_data,
				 &state->out_data);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS rpcint_bh_raw_call_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags)
{
	struct rpcint_bh_raw_call_state *state =
		tevent_req_data(req,
		struct rpcint_bh_raw_call_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_data = talloc_move(mem_ctx, &state->out_data.data);
	*out_length = state->out_data.length;
	*out_flags = 0;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct rpcint_bh_disconnect_state {
	uint8_t _dummy;
};

static struct tevent_req *rpcint_bh_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h)
{
	struct rpcint_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpcint_bh_state);
	struct tevent_req *req;
	struct rpcint_bh_disconnect_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct rpcint_bh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	ok = rpcint_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	/*
	 * TODO: do a real async disconnect ...
	 *
	 * For now the caller needs to free pipes_struct
	 */
	hs->p = NULL;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS rpcint_bh_disconnect_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static bool rpcint_bh_ref_alloc(struct dcerpc_binding_handle *h)
{
	return true;
}

static void rpcint_bh_do_ndr_print(struct dcerpc_binding_handle *h,
				   int ndr_flags,
				   const void *_struct_ptr,
				   const struct ndr_interface_call *call)
{
	void *struct_ptr = discard_const(_struct_ptr);

	if (DEBUGLEVEL < 11) {
		return;
	}

	if (ndr_flags & NDR_IN) {
		ndr_print_function_debug(call->ndr_print,
					 call->name,
					 ndr_flags,
					 struct_ptr);
	}
	if (ndr_flags & NDR_OUT) {
		ndr_print_function_debug(call->ndr_print,
					 call->name,
					 ndr_flags,
					 struct_ptr);
	}
}

static const struct dcerpc_binding_handle_ops rpcint_bh_ops = {
	.name			= "rpcint",
	.is_connected		= rpcint_bh_is_connected,
	.set_timeout		= rpcint_bh_set_timeout,
	.raw_call_send		= rpcint_bh_raw_call_send,
	.raw_call_recv		= rpcint_bh_raw_call_recv,
	.disconnect_send	= rpcint_bh_disconnect_send,
	.disconnect_recv	= rpcint_bh_disconnect_recv,

	.ref_alloc		= rpcint_bh_ref_alloc,
	.do_ndr_print		= rpcint_bh_do_ndr_print,
};

static NTSTATUS rpcint_binding_handle_ex(TALLOC_CTX *mem_ctx,
			const struct ndr_syntax_id *abstract_syntax,
			const struct ndr_interface_table *ndr_table,
			const struct tsocket_address *remote_address,
			const struct auth_session_info *session_info,
			struct messaging_context *msg_ctx,
			struct dcerpc_binding_handle **binding_handle)
{
	struct dcerpc_binding_handle *h;
	struct rpcint_bh_state *hs;

	if (ndr_table) {
		abstract_syntax = &ndr_table->syntax_id;
	}

	h = dcerpc_binding_handle_create(mem_ctx,
					 &rpcint_bh_ops,
					 NULL,
					 ndr_table,
					 &hs,
					 struct rpcint_bh_state,
					 __location__);
	if (h == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	hs->p = make_internal_rpc_pipe_p(hs,
					 abstract_syntax,
					 remote_address,
					 session_info,
					 msg_ctx);
	if (hs->p == NULL) {
		TALLOC_FREE(h);
		return NT_STATUS_NO_MEMORY;
	}

	*binding_handle = h;
	return NT_STATUS_OK;
}
/**
 * @brief Create a new DCERPC Binding Handle which uses a local dispatch function.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  ndr_table Normally the ndr_table_<name>.
 *
 * @param[in]  remote_address The info about the connected client.
 *
 * @param[in]  serversupplied_info The server supplied authentication function.
 *
 * @param[in]  msg_ctx   The messaging context that can be used by the server
 *
 * @param[out] binding_handle  A pointer to store the connected
 *                             dcerpc_binding_handle
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occured.
 *
 * @code
 *   struct dcerpc_binding_handle *winreg_binding;
 *   NTSTATUS status;
 *
 *   status = rpcint_binding_handle(tmp_ctx,
 *                                  &ndr_table_winreg,
 *                                  p->remote_address,
 *                                  p->session_info,
 *                                  p->msg_ctx
 *                                  &winreg_binding);
 * @endcode
 */
NTSTATUS rpcint_binding_handle(TALLOC_CTX *mem_ctx,
			       const struct ndr_interface_table *ndr_table,
			       const struct tsocket_address *remote_address,
			       const struct auth_session_info *session_info,
			       struct messaging_context *msg_ctx,
			       struct dcerpc_binding_handle **binding_handle)
{
	return rpcint_binding_handle_ex(mem_ctx, NULL, ndr_table, remote_address,
					session_info, msg_ctx, binding_handle);
}

/**
 * @internal
 *
 * @brief Create a new RPC client context which uses a local transport.
 *
 * This creates a local transport. It is a shortcut to directly call the server
 * functions and avoid marshalling.
 * NOTE: this function should be used only by rpc_pipe_open_interface()
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  abstract_syntax Normally the syntax_id of the autogenerated
 *                             ndr_table_<name>.
 *
 * @param[in]  serversupplied_info The server supplied authentication function.
 *
 * @param[in]  remote_address The client address information.
 *
 * @param[in]  msg_ctx  The messaging context to use.
 *
 * @param[out] presult  A pointer to store the connected rpc client pipe.
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occured.
 */
NTSTATUS rpc_pipe_open_internal(TALLOC_CTX *mem_ctx,
				const struct ndr_syntax_id *abstract_syntax,
				const struct auth_session_info *session_info,
				const struct tsocket_address *remote_address,
				struct messaging_context *msg_ctx,
				struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	NTSTATUS status;

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->abstract_syntax = *abstract_syntax;
	result->transfer_syntax = ndr_transfer_syntax_ndr;

	if (remote_address == NULL) {
		struct tsocket_address *local;
		int rc;

		rc = tsocket_address_inet_from_strings(mem_ctx,
						       "ip",
						       "127.0.0.1",
						       0,
						       &local);
		if (rc < 0) {
			TALLOC_FREE(result);
			return NT_STATUS_NO_MEMORY;
		}

		remote_address = local;
	}

	result->max_xmit_frag = -1;

	status = rpcint_binding_handle_ex(result,
					  abstract_syntax,
					  NULL,
					  remote_address,
					  session_info,
					  msg_ctx,
					  &result->binding_handle);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(result);
		return status;
	}

	*presult = result;
	return NT_STATUS_OK;
}

/****************************************************************************
 * External pipes functions
 ***************************************************************************/

NTSTATUS make_external_rpc_pipe(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *local_address,
				const struct tsocket_address *remote_address,
				const struct auth_session_info *session_info,
				struct npa_state **pnpa)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct auth_session_info_transport *session_info_t;
	struct tevent_context *ev_ctx;
	struct tevent_req *subreq;
	const char *socket_np_dir;
	const char *socket_dir;
	struct npa_state *npa;
	int sys_errno;
	NTSTATUS status;
	int rc = -1;
	bool ok;

	npa = npa_state_init(tmp_ctx);
	if (npa == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	socket_dir = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					  "external_rpc_pipe",
					  "socket_dir",
					  lp_ncalrpc_dir());
	if (socket_dir == NULL) {
		DEBUG(0, ("external_rpc_pipe: socket_dir not set\n"));
		status = NT_STATUS_PIPE_NOT_AVAILABLE;
		goto out;
	}

	socket_np_dir = talloc_asprintf(tmp_ctx, "%s/np", socket_dir);
	if (socket_np_dir == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	session_info_t = talloc_zero(tmp_ctx,
				     struct auth_session_info_transport);
	if (session_info_t == NULL) {
		DEBUG(0, ("talloc failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	session_info_t->session_info = copy_session_info(session_info_t,
							 session_info);
	if (session_info_t->session_info == NULL) {
		DEBUG(0, ("copy_session_info failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ev_ctx = s3_tevent_context_init(tmp_ctx);
	if (ev_ctx == NULL) {
		DEBUG(0, ("s3_tevent_context_init failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	become_root();
	subreq = tstream_npa_connect_send(tmp_ctx,
					  ev_ctx,
					  socket_np_dir,
					  pipe_name,
					  remote_address, /* client_addr */
					  NULL, /* client_name */
					  local_address, /* server_addr */
					  NULL, /* server_name */
					  session_info_t);
	if (subreq == NULL) {
		unbecome_root();
		DEBUG(0, ("tstream_npa_connect_send to %s for pipe %s and "
			  "user %s\\%s failed\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}
	ok = tevent_req_poll(subreq, ev_ctx);
	unbecome_root();
	if (!ok) {
		DEBUG(0, ("tevent_req_poll to %s for pipe %s and user %s\\%s "
			  "failed for tstream_npa_connect: %s\n",
			  socket_np_dir,
			  pipe_name,
			  session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(errno)));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	rc = tstream_npa_connect_recv(subreq,
				      &sys_errno,
				      npa,
				      &npa->stream,
				      &npa->file_type,
				      &npa->device_state,
				      &npa->allocation_size);
	talloc_free(subreq);
	if (rc != 0) {
		int l = 1;

		if (errno == ENOENT) {
			l = 2;
		}

		DEBUG(l, ("tstream_npa_connect_recv  to %s for pipe %s and "
			  "user %s\\%s failed: %s\n",
			  socket_np_dir,
			  pipe_name,
			  session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(sys_errno)));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	*pnpa = talloc_steal(mem_ctx, npa);
	status = NT_STATUS_OK;
out:
	talloc_free(tmp_ctx);

	return status;
}

struct np_proxy_state *make_external_rpc_pipe_p(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *local_address,
				const struct tsocket_address *remote_address,
				const struct auth_session_info *session_info)
{
	struct np_proxy_state *result;
	char *socket_np_dir;
	const char *socket_dir;
	struct tevent_context *ev;
	struct tevent_req *subreq;
	struct auth_session_info_transport *session_info_t;
	bool ok;
	int ret;
	int sys_errno;

	result = talloc(mem_ctx, struct np_proxy_state);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->read_queue = tevent_queue_create(result, "np_read");
	if (result->read_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	result->write_queue = tevent_queue_create(result, "np_write");
	if (result->write_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	ev = s3_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		DEBUG(0, ("s3_tevent_context_init failed\n"));
		goto fail;
	}

	socket_dir = lp_parm_const_string(
		GLOBAL_SECTION_SNUM, "external_rpc_pipe", "socket_dir",
		lp_ncalrpc_dir());
	if (socket_dir == NULL) {
		DEBUG(0, ("external_rpc_pipe:socket_dir not set\n"));
		goto fail;
	}
	socket_np_dir = talloc_asprintf(talloc_tos(), "%s/np", socket_dir);
	if (socket_np_dir == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		goto fail;
	}

	session_info_t = talloc_zero(talloc_tos(), struct auth_session_info_transport);
	if (session_info_t == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	session_info_t->session_info = copy_session_info(session_info_t,
							 session_info);
	if (session_info_t->session_info == NULL) {
		DEBUG(0, ("copy_session_info failed\n"));
		goto fail;
	}

	become_root();
	subreq = tstream_npa_connect_send(talloc_tos(), ev,
					  socket_np_dir,
					  pipe_name,
					  remote_address, /* client_addr */
					  NULL, /* client_name */
					  local_address, /* server_addr */
					  NULL, /* server_name */
					  session_info_t);
	if (subreq == NULL) {
		unbecome_root();
		DEBUG(0, ("tstream_npa_connect_send to %s for pipe %s and "
			  "user %s\\%s failed\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name));
		goto fail;
	}
	ok = tevent_req_poll(subreq, ev);
	unbecome_root();
	if (!ok) {
		DEBUG(0, ("tevent_req_poll to %s for pipe %s and user %s\\%s "
			  "failed for tstream_npa_connect: %s\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(errno)));
		goto fail;

	}
	ret = tstream_npa_connect_recv(subreq, &sys_errno,
				       result,
				       &result->npipe,
				       &result->file_type,
				       &result->device_state,
				       &result->allocation_size);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		int l = 1;
		if (errno == ENOENT) {
			l = 2;
		}
		DEBUG(l, ("tstream_npa_connect_recv  to %s for pipe %s and "
			  "user %s\\%s failed: %s\n",
			  socket_np_dir, pipe_name, session_info_t->session_info->info->domain_name,
			  session_info_t->session_info->info->account_name,
			  strerror(sys_errno)));
		goto fail;
	}

	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static NTSTATUS rpc_pipe_open_external(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct ndr_interface_table *table,
				const struct auth_session_info *session_info,
				struct rpc_pipe_client **_result)
{
	struct tsocket_address *local, *remote;
	struct rpc_pipe_client *result = NULL;
	struct np_proxy_state *proxy_state = NULL;
	struct pipe_auth_data *auth;
	NTSTATUS status;
	int ret;

	/* this is an internal connection, fake up ip addresses */
	ret = tsocket_address_inet_from_strings(talloc_tos(), "ip",
						NULL, 0, &local);
	if (ret) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = tsocket_address_inet_from_strings(talloc_tos(), "ip",
						NULL, 0, &remote);
	if (ret) {
		return NT_STATUS_NO_MEMORY;
	}

	proxy_state = make_external_rpc_pipe_p(mem_ctx, pipe_name,
						local, remote, session_info);
	if (!proxy_state) {
		DEBUG(1, ("Unable to make proxy_state for connection to %s.\n", pipe_name));
		return NT_STATUS_UNSUCCESSFUL;
	}

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result->abstract_syntax = table->syntax_id;
	result->transfer_syntax = ndr_transfer_syntax_ndr;

	result->desthost = get_myname(result);
	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if ((result->desthost == NULL) || (result->srv_name_slash == NULL)) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;

	status = rpc_transport_tstream_init(result,
					    &proxy_state->npipe,
					    &result->transport);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	result->binding_handle = rpccli_bh_create(result, NULL, table);
	if (result->binding_handle == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0, ("Failed to create binding handle.\n"));
		goto done;
	}

	result->auth = talloc_zero(result, struct pipe_auth_data);
	if (!result->auth) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	result->auth->auth_type = DCERPC_AUTH_TYPE_NONE;
	result->auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
	result->auth->auth_context_id = 0;

	status = rpccli_anon_bind_data(result, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to initialize anonymous bind.\n"));
		goto done;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to bind external pipe.\n"));
		goto done;
	}

done:
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(result);
	}
	TALLOC_FREE(proxy_state);
	*_result = result;
	return status;
}

/**
 * @brief Create a new RPC client context which uses a local dispatch function
 *	  or a remote transport, depending on rpc_server configuration for the
 *	  specific service.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  abstract_syntax Normally the syntax_id of the autogenerated
 *                             ndr_table_<name>.
 *
 * @param[in]  serversupplied_info The server supplied authentication function.
 *
 * @param[in]  remote_address The client address information.
 *
 * @param[in]  msg_ctx  The messaging context to use.
 *
 * @param[out] presult  A pointer to store the connected rpc client pipe.
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occured.
 *
 * @code
 *   struct rpc_pipe_client *winreg_pipe;
 *   NTSTATUS status;
 *
 *   status = rpc_pipe_open_interface(tmp_ctx,
 *                                    &ndr_table_winreg.syntax_id,
 *                                    p->session_info,
 *                                    remote_address,
 *                                    &winreg_pipe);
 * @endcode
 */

NTSTATUS rpc_pipe_open_interface(TALLOC_CTX *mem_ctx,
				 const struct ndr_interface_table *table,
				 const struct auth_session_info *session_info,
				 const struct tsocket_address *remote_address,
				 struct messaging_context *msg_ctx,
				 struct rpc_pipe_client **cli_pipe)
{
	struct rpc_pipe_client *cli = NULL;
	enum rpc_service_mode_e pipe_mode;
	const char *pipe_name;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	if (cli_pipe != NULL) {
		if (rpccli_is_connected(*cli_pipe)) {
			return NT_STATUS_OK;
		} else {
			TALLOC_FREE(*cli_pipe);
		}
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pipe_name = dcerpc_default_transport_endpoint(mem_ctx, NCACN_NP, table);
	if (pipe_name == NULL) {
		DEBUG(1, ("Unable to find pipe name to forward %s to.\n", table->name));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	while (pipe_name[0] == '\\') {
		pipe_name++;
	}

	DEBUG(5, ("Connecting to %s pipe.\n", pipe_name));

	pipe_mode = rpc_service_mode(pipe_name);

	switch (pipe_mode) {
	case RPC_SERVICE_MODE_EMBEDDED:
		status = rpc_pipe_open_internal(tmp_ctx,
						&table->syntax_id, session_info,
						remote_address, msg_ctx,
						&cli);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		break;
	case RPC_SERVICE_MODE_EXTERNAL:
		/* It would be nice to just use rpc_pipe_open_ncalrpc() but
		 * for now we need to use the special proxy setup to connect
		 * to spoolssd. */

		status = rpc_pipe_open_external(tmp_ctx,
						pipe_name, table,
						session_info,
						&cli);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		break;
	case RPC_SERVICE_MODE_DISABLED:
		status = NT_STATUS_NOT_IMPLEMENTED;
		DEBUG(0, ("Service pipe %s is disabled in config file: %s",
			  pipe_name, nt_errstr(status)));
		goto done;
        }

	status = NT_STATUS_OK;
done:
	if (NT_STATUS_IS_OK(status) && cli_pipe != NULL) {
		*cli_pipe = talloc_move(mem_ctx, &cli);
	}
	TALLOC_FREE(tmp_ctx);
	return status;
}
