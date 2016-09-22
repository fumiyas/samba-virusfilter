/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Almost completely rewritten by (C) Jeremy Allison 2005 - 2010
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

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 */

#include "includes.h"
#include "system/filesys.h"
#include "srv_pipe_internal.h"
#include "../librpc/gen_ndr/ndr_dcerpc.h"
#include "../librpc/rpc/rpc_common.h"
#include "dcesrv_auth_generic.h"
#include "rpc_server.h"
#include "rpc_dce.h"
#include "smbd/smbd.h"
#include "auth.h"
#include "ntdomain.h"
#include "rpc_server/srv_pipe.h"
#include "rpc_server/rpc_contexts.h"
#include "lib/param/param.h"
#include "librpc/ndr/ndr_table.h"
#include "auth/gensec/gensec.h"
#include "librpc/ndr/ndr_dcerpc.h"
#include "lib/tsocket/tsocket.h"
#include "../librpc/gen_ndr/ndr_samr.h"
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../librpc/gen_ndr/ndr_epmapper.h"
#include "../librpc/gen_ndr/ndr_echo.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static NTSTATUS pipe_auth_verify_final(struct pipes_struct *p);

/**
 * Dump everything from the start of the end up of the provided data
 * into a file, but only at debug level >= 50
 **/
static void dump_pdu_region(const char *name, int v,
			    DATA_BLOB *data, size_t start, size_t end)
{
	int fd, i;
	char *fname = NULL;
	ssize_t sz;

	if (DEBUGLEVEL < 50) return;

	if (start > data->length || end > data->length || start > end) return;

	for (i = 1; i < 100; i++) {
		if (v != -1) {
			fname = talloc_asprintf(talloc_tos(),
						"/tmp/%s_%d.%d.prs",
						name, v, i);
		} else {
			fname = talloc_asprintf(talloc_tos(),
						"/tmp/%s_%d.prs",
						name, i);
		}
		if (!fname) {
			return;
		}
		fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0644);
		if (fd != -1 || errno != EEXIST) break;
	}
	if (fd != -1) {
		sz = write(fd, data->data + start, end - start);
		i = close(fd);
		if ((sz != end - start) || (i != 0) ) {
			DEBUG(0, ("Error writing/closing %s: %ld!=%ld %d\n",
				  fname, (unsigned long)sz,
				  (unsigned long)end - start, i));
		} else {
			DEBUG(0,("created %s\n", fname));
		}
	}
	TALLOC_FREE(fname);
}

static DATA_BLOB generic_session_key(void)
{
	return data_blob_const("SystemLibraryDTC", 16);
}

/*******************************************************************
 Generate the next PDU to be returned from the data.
********************************************************************/

static NTSTATUS create_next_packet(TALLOC_CTX *mem_ctx,
				   struct pipe_auth_data *auth,
				   uint32_t call_id,
				   DATA_BLOB *rdata,
				   size_t data_sent_length,
				   DATA_BLOB *frag,
				   size_t *pdu_size)
{
	union dcerpc_payload u;
	uint8_t pfc_flags;
	size_t data_left;
	size_t data_to_send;
	size_t frag_len;
	size_t pad_len = 0;
	size_t auth_len = 0;
	NTSTATUS status;

	ZERO_STRUCT(u.response);

	/* Set up rpc packet pfc flags. */
	if (data_sent_length == 0) {
		pfc_flags = DCERPC_PFC_FLAG_FIRST;
	} else {
		pfc_flags = 0;
	}

	/* Work out how much we can fit in a single PDU. */
	data_left = rdata->length - data_sent_length;

	/* Ensure there really is data left to send. */
	if (!data_left) {
		DEBUG(0, ("No data left to send !\n"));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	status = dcerpc_guess_sizes(auth,
				    DCERPC_RESPONSE_LENGTH,
				    data_left,
				    RPC_MAX_PDU_FRAG_LEN,
				    &data_to_send, &frag_len,
				    &auth_len, &pad_len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Set up the alloc hint. This should be the data left to send. */
	u.response.alloc_hint = data_left;

	/* Work out if this PDU will be the last. */
	if (data_sent_length + data_to_send >= rdata->length) {
		pfc_flags |= DCERPC_PFC_FLAG_LAST;
	}

	/* Prepare data to be NDR encoded. */
	u.response.stub_and_verifier =
		data_blob_const(rdata->data + data_sent_length, data_to_send);

	/* Store the packet in the data stream. */
	status = dcerpc_push_ncacn_packet(mem_ctx, DCERPC_PKT_RESPONSE,
					  pfc_flags, auth_len, call_id,
					  &u, frag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall RPC Packet.\n"));
		return status;
	}

	if (auth_len) {
		/* Set the proper length on the pdu, including padding.
		 * Only needed if an auth trailer will be appended. */
		dcerpc_set_frag_length(frag, frag->length
						+ pad_len
						+ DCERPC_AUTH_TRAILER_LENGTH
						+ auth_len);
	}

	if (auth_len) {
		status = dcerpc_add_auth_footer(auth, pad_len, frag);
		if (!NT_STATUS_IS_OK(status)) {
			data_blob_free(frag);
			return status;
		}
	}

	*pdu_size = data_to_send;
	return NT_STATUS_OK;
}

/*******************************************************************
 Generate the next PDU to be returned from the data in p->rdata. 
********************************************************************/

bool create_next_pdu(struct pipes_struct *p)
{
	size_t pdu_size = 0;
	NTSTATUS status;

	/*
	 * If we're in the fault state, keep returning fault PDU's until
	 * the pipe gets closed. JRA.
	 */
	if (p->fault_state) {
		setup_fault_pdu(p, NT_STATUS(p->fault_state));
		return true;
	}

	status = create_next_packet(p->mem_ctx, &p->auth,
				    p->call_id, &p->out_data.rdata,
				    p->out_data.data_sent_length,
				    &p->out_data.frag, &pdu_size);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to create packet with error %s, "
			  "(auth level %u / type %u)\n",
			  nt_errstr(status),
			  (unsigned int)p->auth.auth_level,
			  (unsigned int)p->auth.auth_type));
		return false;
	}

	/* Setup the counts for this PDU. */
	p->out_data.data_sent_length += pdu_size;
	p->out_data.current_pdu_sent = 0;
	return true;
}


static bool pipe_init_outgoing_data(struct pipes_struct *p);

/*******************************************************************
 Marshall a bind_nak pdu.
*******************************************************************/

static bool setup_bind_nak(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	NTSTATUS status;
	union dcerpc_payload u;

	/* Free any memory in the current return data buffer. */
	pipe_init_outgoing_data(p);

	/*
	 * Initialize a bind_nak header.
	 */

	ZERO_STRUCT(u);

	u.bind_nak.reject_reason  = 0;

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_BIND_NAK,
					  DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
					  0,
					  pkt->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	set_incoming_fault(p);
	TALLOC_FREE(p->auth.auth_ctx);
	p->auth.auth_level = DCERPC_AUTH_LEVEL_NONE;
	p->auth.auth_type = DCERPC_AUTH_TYPE_NONE;
	p->pipe_bound = False;
	p->allow_bind = false;
	p->allow_alter = false;
	p->allow_auth3 = false;

	return True;
}

/*******************************************************************
 Marshall a fault pdu.
*******************************************************************/

bool setup_fault_pdu(struct pipes_struct *p, NTSTATUS fault_status)
{
	NTSTATUS status;
	union dcerpc_payload u;

	/* Free any memory in the current return data buffer. */
	pipe_init_outgoing_data(p);

	/*
	 * Initialize a fault header.
	 */

	ZERO_STRUCT(u);

	u.fault.status		= NT_STATUS_V(fault_status);
	u.fault._pad		= data_blob_talloc_zero(p->mem_ctx, 4);

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_FAULT,
					  DCERPC_PFC_FLAG_FIRST |
					   DCERPC_PFC_FLAG_LAST |
					   DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
					  0,
					  p->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	return True;
}

/*******************************************************************
 Ensure a bind request has the correct abstract & transfer interface.
 Used to reject unknown binds from Win2k.
*******************************************************************/

static bool check_bind_req(struct pipes_struct *p,
			   struct ndr_syntax_id* abstract,
			   struct ndr_syntax_id* transfer,
			   uint32_t context_id)
{
	struct pipe_rpc_fns *context_fns;
	bool ok;
	const char *interface_name = NULL;

	DEBUG(3,("check_bind_req for %s context_id=%u\n",
		 ndr_interface_name(&abstract->uuid,
				    abstract->if_version),
		 (unsigned)context_id));

	ok = ndr_syntax_id_equal(transfer, &ndr_transfer_syntax_ndr);
	if (!ok) {
		DEBUG(1,("check_bind_req unknown transfer syntax for "
			 "%s context_id=%u\n",
			 ndr_interface_name(&abstract->uuid,
				    abstract->if_version),
			 (unsigned)context_id));
		return false;
	}

	for (context_fns = p->contexts;
	     context_fns != NULL;
	     context_fns = context_fns->next)
	{
		if (context_fns->context_id != context_id) {
			continue;
		}

		ok = ndr_syntax_id_equal(&context_fns->syntax,
					 abstract);
		if (ok) {
			return true;
		}

		DEBUG(1,("check_bind_req: changing abstract syntax for "
			 "%s context_id=%u into %s not supported\n",
			 ndr_interface_name(&context_fns->syntax.uuid,
					    context_fns->syntax.if_version),
			 (unsigned)context_id,
			 ndr_interface_name(&abstract->uuid,
					    abstract->if_version)));
		return false;
	}

	/* we have to check all now since win2k introduced a new UUID on the lsaprpc pipe */
	if (!rpc_srv_pipe_exists_by_id(abstract)) {
		return false;
	}

	DEBUG(3, ("check_bind_req: %s -> %s rpc service\n",
		  rpc_srv_get_pipe_cli_name(abstract),
		  rpc_srv_get_pipe_srv_name(abstract)));

	ok = init_pipe_handles(p, abstract);
	if (!ok) {
		DEBUG(1, ("Failed to init pipe handles!\n"));
		return false;
	}

	context_fns = talloc_zero(p, struct pipe_rpc_fns);
	if (context_fns == NULL) {
		DEBUG(0,("check_bind_req: talloc() failed!\n"));
		return false;
	}

	interface_name = ndr_interface_name(&abstract->uuid,
					    abstract->if_version);
	SMB_ASSERT(interface_name != NULL);

	context_fns->next = context_fns->prev = NULL;
	context_fns->n_cmds = rpc_srv_get_pipe_num_cmds(abstract);
	context_fns->cmds = rpc_srv_get_pipe_cmds(abstract);
	context_fns->context_id = context_id;
	context_fns->syntax = *abstract;

	context_fns->allow_connect = lp_allow_dcerpc_auth_level_connect();
	/*
	 * for the samr, lsarpc and netlogon interfaces we don't allow "connect"
	 * auth_level by default.
	 */
	ok = ndr_syntax_id_equal(abstract, &ndr_table_samr.syntax_id);
	if (ok) {
		context_fns->allow_connect = false;
	}
	ok = ndr_syntax_id_equal(abstract, &ndr_table_lsarpc.syntax_id);
	if (ok) {
		context_fns->allow_connect = false;
	}
	ok = ndr_syntax_id_equal(abstract, &ndr_table_netlogon.syntax_id);
	if (ok) {
		context_fns->allow_connect = false;
	}
	/*
	 * for the epmapper and echo interfaces we allow "connect"
	 * auth_level by default.
	 */
	ok = ndr_syntax_id_equal(abstract, &ndr_table_epmapper.syntax_id);
	if (ok) {
		context_fns->allow_connect = true;
	}
	ok = ndr_syntax_id_equal(abstract, &ndr_table_rpcecho.syntax_id);
	if (ok) {
		context_fns->allow_connect = true;
	}
	/*
	 * every interface can be modified to allow "connect" auth_level by
	 * using a parametric option like:
	 * allow dcerpc auth level connect:<interface>
	 * e.g.
	 * allow dcerpc auth level connect:samr = yes
	 */
	context_fns->allow_connect = lp_parm_bool(-1,
		"allow dcerpc auth level connect",
		interface_name, context_fns->allow_connect);

	/* add to the list of open contexts */

	DLIST_ADD( p->contexts, context_fns );

	return True;
}

/**
 * Is a named pipe known?
 * @param[in] pipename		Just the filename
 * @result			Do we want to serve this?
 */
bool is_known_pipename(const char *pipename, struct ndr_syntax_id *syntax)
{
	NTSTATUS status;

	if (lp_disable_spoolss() && strequal(pipename, "spoolss")) {
		DEBUG(10, ("refusing spoolss access\n"));
		return false;
	}

	if (rpc_srv_get_pipe_interface_by_cli_name(pipename, syntax)) {
		return true;
	}

	status = smb_probe_module("rpc", pipename);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("is_known_pipename: %s unknown\n", pipename));
		return false;
	}
	DEBUG(10, ("is_known_pipename: %s loaded dynamically\n", pipename));

	/*
	 * Scan the list again for the interface id
	 */
	if (rpc_srv_get_pipe_interface_by_cli_name(pipename, syntax)) {
		return true;
	}

	DEBUG(10, ("is_known_pipename: pipe %s did not register itself!\n",
		   pipename));

	return false;
}

/*******************************************************************
 Handle an NTLMSSP bind auth.
*******************************************************************/

static bool pipe_auth_generic_bind(struct pipes_struct *p,
				   struct ncacn_packet *pkt,
				   struct dcerpc_auth *auth_info,
				   DATA_BLOB *response)
{
	TALLOC_CTX *mem_ctx = pkt;
	struct gensec_security *gensec_security = NULL;
        NTSTATUS status;

	status = auth_generic_server_authtype_start(p,
						    auth_info->auth_type,
						    auth_info->auth_level,
						    &auth_info->credentials,
						    response,
						    p->remote_address,
						    &gensec_security);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED))
	{
		DEBUG(0, (__location__ ": auth_generic_server_authtype_start[%u/%u] failed: %s\n",
			  auth_info->auth_type, auth_info->auth_level, nt_errstr(status)));
		return false;
	}

	/* Make sure data is bound to the memctx, to be freed the caller */
	talloc_steal(mem_ctx, response->data);

	p->auth.auth_ctx = gensec_security;
	p->auth.auth_type = auth_info->auth_type;
	p->auth.auth_level = auth_info->auth_level;
	p->auth.auth_context_id = auth_info->auth_context_id;

	if (pkt->pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN) {
		p->auth.client_hdr_signing = true;
		p->auth.hdr_signing = gensec_have_feature(gensec_security,
						GENSEC_FEATURE_SIGN_PKT_HEADER);
	}

	if (p->auth.hdr_signing) {
		gensec_want_feature(gensec_security,
				    GENSEC_FEATURE_SIGN_PKT_HEADER);
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return true;
	}

	status = pipe_auth_verify_final(p);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("pipe_auth_verify_final failed: %s\n",
			  nt_errstr(status)));
		return false;
	}

	return true;
}

/*******************************************************************
 Process an NTLMSSP authentication response.
 If this function succeeds, the user has been authenticated
 and their domain, name and calling workstation stored in
 the pipe struct.
*******************************************************************/

static bool pipe_auth_generic_verify_final(TALLOC_CTX *mem_ctx,
				struct gensec_security *gensec_security,
				enum dcerpc_AuthLevel auth_level,
				struct auth_session_info **session_info)
{
	NTSTATUS status;
	bool ret;

	DEBUG(5, (__location__ ": checking user details\n"));

	/* Finally - if the pipe negotiated integrity (sign) or privacy (seal)
	   ensure the underlying NTLMSSP flags are also set. If not we should
	   refuse the bind. */

	status = auth_generic_server_check_flags(gensec_security,
					    (auth_level ==
						DCERPC_AUTH_LEVEL_INTEGRITY),
					    (auth_level ==
						DCERPC_AUTH_LEVEL_PRIVACY));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, (__location__ ": Client failed to negotatie proper "
			  "security for rpc connection\n"));
		return false;
	}

	TALLOC_FREE(*session_info);

	status = auth_generic_server_get_user_info(gensec_security,
						mem_ctx, session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, (__location__ ": failed to obtain the server info "
			  "for authenticated user: %s\n", nt_errstr(status)));
		return false;
	}

	if ((*session_info)->security_token == NULL) {
		DEBUG(1, ("Auth module failed to provide nt_user_token\n"));
		return false;
	}

	if ((*session_info)->unix_token == NULL) {
		DEBUG(1, ("Auth module failed to provide unix_token\n"));
		return false;
	}

	/*
	 * We're an authenticated bind over smb, so the session key needs to
	 * be set to "SystemLibraryDTC". Weird, but this is what Windows
	 * does. See the RPC-SAMBA3SESSIONKEY.
	 */

	ret = session_info_set_session_key((*session_info), generic_session_key());
	if (!ret) {
		DEBUG(0, ("Failed to set session key!\n"));
		return false;
	}

	return true;
}

static NTSTATUS pipe_auth_verify_final(struct pipes_struct *p)
{
	struct gensec_security *gensec_security;
	bool ok;

	if (p->auth.auth_type == DCERPC_AUTH_TYPE_NONE) {
		p->pipe_bound = true;
		return NT_STATUS_OK;
	}

	gensec_security = p->auth.auth_ctx;

	ok = pipe_auth_generic_verify_final(p, gensec_security,
					    p->auth.auth_level,
					    &p->session_info);
	if (!ok) {
		return NT_STATUS_ACCESS_DENIED;
	}

	p->pipe_bound = true;

	return NT_STATUS_OK;
}

/*******************************************************************
 Respond to a pipe bind request.
*******************************************************************/

static bool api_pipe_bind_req(struct pipes_struct *p,
				struct ncacn_packet *pkt)
{
	struct dcerpc_auth auth_info = {0};
	uint16_t assoc_gid;
	NTSTATUS status;
	struct ndr_syntax_id id;
	uint8_t pfc_flags = 0;
	union dcerpc_payload u;
	struct dcerpc_ack_ctx bind_ack_ctx;
	DATA_BLOB auth_resp = data_blob_null;
	DATA_BLOB auth_blob = data_blob_null;
	const struct ndr_interface_table *table;

	if (!p->allow_bind) {
		DEBUG(2,("Pipe not in allow bind state\n"));
		return setup_bind_nak(p, pkt);
	}
	p->allow_bind = false;

	status = dcerpc_verify_ncacn_packet_header(pkt,
			DCERPC_PKT_BIND,
			pkt->u.bind.auth_info.length,
			0, /* required flags */
			DCERPC_PFC_FLAG_FIRST |
			DCERPC_PFC_FLAG_LAST |
			DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
			0x08 | /* this is not defined, but should be ignored */
			DCERPC_PFC_FLAG_CONC_MPX |
			DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
			DCERPC_PFC_FLAG_MAYBE |
			DCERPC_PFC_FLAG_OBJECT_UUID);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("api_pipe_bind_req: invalid pdu: %s\n",
			  nt_errstr(status)));
		NDR_PRINT_DEBUG(ncacn_packet, pkt);
		goto err_exit;
	}

	if (pkt->u.bind.num_contexts == 0) {
		DEBUG(1, ("api_pipe_bind_req: no rpc contexts around\n"));
		goto err_exit;
	}

	if (pkt->u.bind.ctx_list[0].num_transfer_syntaxes == 0) {
		DEBUG(1, ("api_pipe_bind_req: no transfer syntaxes around\n"));
		goto err_exit;
	}

	/*
	 * Try and find the correct pipe name to ensure
	 * that this is a pipe name we support.
	 */
	id = pkt->u.bind.ctx_list[0].abstract_syntax;

	table = ndr_table_by_uuid(&id.uuid);
	if (table == NULL) {
		DEBUG(0,("unknown interface\n"));
		return false;
	}

	if (rpc_srv_pipe_exists_by_id(&id)) {
		DEBUG(3, ("api_pipe_bind_req: %s -> %s rpc service\n",
			  rpc_srv_get_pipe_cli_name(&id),
			  rpc_srv_get_pipe_srv_name(&id)));
	} else {
		status = smb_probe_module(
			"rpc", dcerpc_default_transport_endpoint(pkt,
				NCACN_NP, table));

		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(3,("api_pipe_bind_req: Unknown rpc service name "
                                 "%s in bind request.\n",
				 ndr_interface_name(&id.uuid,
						    id.if_version)));

			return setup_bind_nak(p, pkt);
		}

		if (rpc_srv_get_pipe_interface_by_cli_name(
				dcerpc_default_transport_endpoint(pkt,
					NCACN_NP, table),
				&id)) {
			DEBUG(3, ("api_pipe_bind_req: %s -> %s rpc service\n",
				  rpc_srv_get_pipe_cli_name(&id),
				  rpc_srv_get_pipe_srv_name(&id)));
		} else {
			DEBUG(0, ("module %s doesn't provide functions for "
				  "pipe %s!\n",
				  ndr_interface_name(&id.uuid,
						     id.if_version),
				  ndr_interface_name(&id.uuid,
						     id.if_version)));
			return setup_bind_nak(p, pkt);
		}
	}

	DEBUG(5,("api_pipe_bind_req: make response. %d\n", __LINE__));

	if (pkt->u.bind.assoc_group_id != 0) {
		assoc_gid = pkt->u.bind.assoc_group_id;
	} else {
		assoc_gid = 0x53f0;
	}

	/*
	 * Create the bind response struct.
	 */

	/* If the requested abstract synt uuid doesn't match our client pipe,
		reject the bind_ack & set the transfer interface synt to all 0's,
		ver 0 (observed when NT5 attempts to bind to abstract interfaces
		unknown to NT4)
		Needed when adding entries to a DACL from NT5 - SK */

	if (check_bind_req(p,
			&pkt->u.bind.ctx_list[0].abstract_syntax,
			&pkt->u.bind.ctx_list[0].transfer_syntaxes[0],
			pkt->u.bind.ctx_list[0].context_id)) {

		bind_ack_ctx.result = 0;
		bind_ack_ctx.reason.value = 0;
		bind_ack_ctx.syntax = pkt->u.bind.ctx_list[0].transfer_syntaxes[0];
	} else {
		/* Rejection reason: abstract syntax not supported */
		bind_ack_ctx.result = DCERPC_BIND_PROVIDER_REJECT;
		bind_ack_ctx.reason.value = DCERPC_BIND_REASON_ASYNTAX;
		bind_ack_ctx.syntax = ndr_syntax_id_null;
	}

	/*
	 * Check if this is an authenticated bind request.
	 */
	if (pkt->auth_length) {
		/*
		 * Decode the authentication verifier.
		 */
		status = dcerpc_pull_auth_trailer(pkt, pkt,
						  &pkt->u.bind.auth_info,
						  &auth_info, NULL, true);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to unmarshall dcerpc_auth.\n"));
			goto err_exit;
		}

		if (!pipe_auth_generic_bind(p, pkt,
					    &auth_info, &auth_resp)) {
			goto err_exit;
		}
	} else {
		p->auth.auth_type = DCERPC_AUTH_TYPE_NONE;
		p->auth.auth_level = DCERPC_AUTH_LEVEL_NONE;
		p->auth.auth_context_id = 0;
	}

	ZERO_STRUCT(u.bind_ack);
	u.bind_ack.max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;
	u.bind_ack.max_recv_frag = RPC_MAX_PDU_FRAG_LEN;
	u.bind_ack.assoc_group_id = assoc_gid;

	/* name has to be \PIPE\xxxxx */
	u.bind_ack.secondary_address =
			talloc_asprintf(pkt, "\\PIPE\\%s",
					rpc_srv_get_pipe_srv_name(&id));
	if (!u.bind_ack.secondary_address) {
		DEBUG(0, ("Out of memory!\n"));
		goto err_exit;
	}
	u.bind_ack.secondary_address_size =
				strlen(u.bind_ack.secondary_address) + 1;

	u.bind_ack.num_results = 1;
	u.bind_ack.ctx_list = &bind_ack_ctx;

	/* NOTE: We leave the auth_info empty so we can calculate the padding
	 * later and then append the auth_info --simo */

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;

	if (p->auth.hdr_signing) {
		pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
	}

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_BIND_ACK,
					  pfc_flags,
					  auth_resp.length,
					  pkt->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall bind_ack packet. (%s)\n",
			  nt_errstr(status)));
		goto err_exit;
	}

	if (auth_resp.length) {
		status = dcerpc_push_dcerpc_auth(pkt,
						 p->auth.auth_type,
						 p->auth.auth_level,
						 0, /* pad_len */
						 p->auth.auth_context_id,
						 &auth_resp,
						 &auth_blob);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Marshalling of dcerpc_auth failed.\n"));
			goto err_exit;
		}
	}

	/* Now that we have the auth len store it into the right place in
	 * the dcerpc header */
	dcerpc_set_frag_length(&p->out_data.frag,
				p->out_data.frag.length + auth_blob.length);

	if (auth_blob.length) {

		if (!data_blob_append(p->mem_ctx, &p->out_data.frag,
					auth_blob.data, auth_blob.length)) {
			DEBUG(0, ("Append of auth info failed.\n"));
			goto err_exit;
		}
	}

	/*
	 * Setup the lengths for the initial reply.
	 */

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	TALLOC_FREE(auth_blob.data);

	if (bind_ack_ctx.result == 0) {
		p->allow_alter = true;
		p->allow_auth3 = true;
		if (p->auth.auth_type == DCERPC_AUTH_TYPE_NONE) {
			status = pipe_auth_verify_final(p);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("pipe_auth_verify_final failed: %s\n",
					  nt_errstr(status)));
				goto err_exit;
			}
		}
	} else {
		goto err_exit;
	}

	return True;

  err_exit:

	data_blob_free(&p->out_data.frag);
	TALLOC_FREE(auth_blob.data);
	return setup_bind_nak(p, pkt);
}

/*******************************************************************
 This is the "stage3" response after a bind request and reply.
*******************************************************************/

bool api_pipe_bind_auth3(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	struct dcerpc_auth auth_info;
	DATA_BLOB response = data_blob_null;
	struct gensec_security *gensec_security;
	NTSTATUS status;

	DEBUG(5, ("api_pipe_bind_auth3: decode request. %d\n", __LINE__));

	if (!p->allow_auth3) {
		DEBUG(1, ("Pipe not in allow auth3 state.\n"));
		goto err;
	}

	status = dcerpc_verify_ncacn_packet_header(pkt,
			DCERPC_PKT_AUTH3,
			pkt->u.auth3.auth_info.length,
			0, /* required flags */
			DCERPC_PFC_FLAG_FIRST |
			DCERPC_PFC_FLAG_LAST |
			DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
			0x08 | /* this is not defined, but should be ignored */
			DCERPC_PFC_FLAG_CONC_MPX |
			DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
			DCERPC_PFC_FLAG_MAYBE |
			DCERPC_PFC_FLAG_OBJECT_UUID);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("api_pipe_bind_auth3: invalid pdu: %s\n",
			  nt_errstr(status)));
		NDR_PRINT_DEBUG(ncacn_packet, pkt);
		goto err;
	}

	/* We can only finish if the pipe is unbound for now */
	if (p->pipe_bound) {
		DEBUG(0, (__location__ ": Pipe already bound, "
			  "AUTH3 not supported!\n"));
		goto err;
	}

	if (pkt->auth_length == 0) {
		DEBUG(1, ("No auth field sent for auth3 request!\n"));
		goto err;
	}

	/*
	 * Decode the authentication verifier response.
	 */

	status = dcerpc_pull_auth_trailer(pkt, pkt,
					  &pkt->u.auth3.auth_info,
					  &auth_info, NULL, true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to unmarshall dcerpc_auth.\n"));
		goto err;
	}

	/* We must NEVER look at auth_info->auth_pad_len here,
	 * as old Samba client code gets it wrong and sends it
	 * as zero. JRA.
	 */

	if (auth_info.auth_type != p->auth.auth_type) {
		DEBUG(1, ("Auth type mismatch! Client sent %d, "
			  "but auth was started as type %d!\n",
			  auth_info.auth_type, p->auth.auth_type));
		goto err;
	}

	if (auth_info.auth_level != p->auth.auth_level) {
		DEBUG(1, ("Auth level mismatch! Client sent %d, "
			  "but auth was started as level %d!\n",
			  auth_info.auth_level, p->auth.auth_level));
		goto err;
	}

	if (auth_info.auth_context_id != p->auth.auth_context_id) {
		DEBUG(0, ("Auth context id mismatch! Client sent %u, "
			  "but auth was started as level %u!\n",
			  (unsigned)auth_info.auth_context_id,
			  (unsigned)p->auth.auth_context_id));
		goto err;
	}

	gensec_security = p->auth.auth_ctx;

	status = auth_generic_server_step(gensec_security,
					  pkt, &auth_info.credentials,
					  &response);

	if (NT_STATUS_EQUAL(status,
			    NT_STATUS_MORE_PROCESSING_REQUIRED) ||
	    response.length) {
		DEBUG(1, (__location__ ": This was supposed to be the final "
			  "leg, but crypto machinery claims a response is "
			  "needed, aborting auth!\n"));
		data_blob_free(&response);
		goto err;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Auth failed (%s)\n", nt_errstr(status)));
		goto err;
	}

	/* Now verify auth was indeed successful and extract server info */
	status = pipe_auth_verify_final(p);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Auth Verify failed (%s)\n", nt_errstr(status)));
		goto err;
	}

	return true;

err:
	p->pipe_bound = false;
	p->allow_bind = false;
	p->allow_alter = false;
	p->allow_auth3 = false;

	TALLOC_FREE(p->auth.auth_ctx);
	return false;
}

/****************************************************************************
 Deal with an alter context call. Can be third part of 3 leg auth request for
 SPNEGO calls.
****************************************************************************/

static bool api_pipe_alter_context(struct pipes_struct *p,
					struct ncacn_packet *pkt)
{
	struct dcerpc_auth auth_info = {0};
	uint16_t assoc_gid;
	NTSTATUS status;
	union dcerpc_payload u;
	struct dcerpc_ack_ctx alter_ack_ctx;
	DATA_BLOB auth_resp = data_blob_null;
	DATA_BLOB auth_blob = data_blob_null;
	struct gensec_security *gensec_security;

	DEBUG(5,("api_pipe_alter_context: make response. %d\n", __LINE__));

	if (!p->allow_alter) {
		DEBUG(1, ("Pipe not in allow alter state.\n"));
		goto err_exit;
	}

	status = dcerpc_verify_ncacn_packet_header(pkt,
			DCERPC_PKT_ALTER,
			pkt->u.alter.auth_info.length,
			0, /* required flags */
			DCERPC_PFC_FLAG_FIRST |
			DCERPC_PFC_FLAG_LAST |
			DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
			0x08 | /* this is not defined, but should be ignored */
			DCERPC_PFC_FLAG_CONC_MPX |
			DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
			DCERPC_PFC_FLAG_MAYBE |
			DCERPC_PFC_FLAG_OBJECT_UUID);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("api_pipe_alter_context: invalid pdu: %s\n",
			  nt_errstr(status)));
		NDR_PRINT_DEBUG(ncacn_packet, pkt);
		goto err_exit;
	}

	if (pkt->u.alter.num_contexts == 0) {
		DEBUG(1, ("api_pipe_alter_context: no rpc contexts around\n"));
		goto err_exit;
	}

	if (pkt->u.alter.ctx_list[0].num_transfer_syntaxes == 0) {
		DEBUG(1, ("api_pipe_alter_context: no transfer syntaxes around\n"));
		goto err_exit;
	}

	if (pkt->u.alter.assoc_group_id != 0) {
		assoc_gid = pkt->u.alter.assoc_group_id;
	} else {
		assoc_gid = 0x53f0;
	}

	/*
	 * Create the bind response struct.
	 */

	/* If the requested abstract synt uuid doesn't match our client pipe,
		reject the alter_ack & set the transfer interface synt to all 0's,
		ver 0 (observed when NT5 attempts to bind to abstract interfaces
		unknown to NT4)
		Needed when adding entries to a DACL from NT5 - SK */

	if (check_bind_req(p,
			&pkt->u.alter.ctx_list[0].abstract_syntax,
			&pkt->u.alter.ctx_list[0].transfer_syntaxes[0],
			pkt->u.alter.ctx_list[0].context_id)) {

		alter_ack_ctx.result = 0;
		alter_ack_ctx.reason.value = 0;
		alter_ack_ctx.syntax = pkt->u.alter.ctx_list[0].transfer_syntaxes[0];
	} else {
		/* Rejection reason: abstract syntax not supported */
		alter_ack_ctx.result = DCERPC_BIND_PROVIDER_REJECT;
		alter_ack_ctx.reason.value = DCERPC_BIND_REASON_ASYNTAX;
		alter_ack_ctx.syntax = ndr_syntax_id_null;
	}

	/*
	 * Check if this is an authenticated alter context request.
	 */
	if (pkt->auth_length) {
		/* We can only finish if the pipe is unbound for now */
		if (p->pipe_bound) {
			DEBUG(0, (__location__ ": Pipe already bound, "
				  "Altering Context not yet supported!\n"));
			goto err_exit;
		}

		status = dcerpc_pull_auth_trailer(pkt, pkt,
						  &pkt->u.alter.auth_info,
						  &auth_info, NULL, true);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to unmarshall dcerpc_auth.\n"));
			goto err_exit;
		}

		if (auth_info.auth_type != p->auth.auth_type) {
			DEBUG(0, ("Auth type mismatch! Client sent %d, "
				  "but auth was started as type %d!\n",
				  auth_info.auth_type, p->auth.auth_type));
			goto err_exit;
		}

		if (auth_info.auth_level != p->auth.auth_level) {
			DEBUG(0, ("Auth level mismatch! Client sent %d, "
				  "but auth was started as level %d!\n",
				  auth_info.auth_level, p->auth.auth_level));
			goto err_exit;
		}

		if (auth_info.auth_context_id != p->auth.auth_context_id) {
			DEBUG(0, ("Auth context id mismatch! Client sent %u, "
				  "but auth was started as level %u!\n",
				  (unsigned)auth_info.auth_context_id,
				  (unsigned)p->auth.auth_context_id));
			goto err_exit;
		}

		gensec_security = p->auth.auth_ctx;
		status = auth_generic_server_step(gensec_security,
						  pkt,
						  &auth_info.credentials,
						  &auth_resp);
		if (NT_STATUS_IS_OK(status)) {
			/* third leg of auth, verify auth info */
			status = pipe_auth_verify_final(p);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("Auth Verify failed (%s)\n",
					  nt_errstr(status)));
				goto err_exit;
			}
		} else if (NT_STATUS_EQUAL(status,
					NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			DEBUG(10, ("More auth legs required.\n"));
		} else {
			DEBUG(0, ("Auth step returned an error (%s)\n",
				  nt_errstr(status)));
			goto err_exit;
		}
	}

	ZERO_STRUCT(u.alter_resp);
	u.alter_resp.max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;
	u.alter_resp.max_recv_frag = RPC_MAX_PDU_FRAG_LEN;
	u.alter_resp.assoc_group_id = assoc_gid;

	/* secondary address CAN be NULL
	 * as the specs say it's ignored.
	 * It MUST be NULL to have the spoolss working.
	 */
	u.alter_resp.secondary_address = "";
	u.alter_resp.secondary_address_size = 1;

	u.alter_resp.num_results = 1;
	u.alter_resp.ctx_list = &alter_ack_ctx;

	/* NOTE: We leave the auth_info empty so we can calculate the padding
	 * later and then append the auth_info --simo */

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_ALTER_RESP,
					  DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
					  auth_resp.length,
					  pkt->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall alter_resp packet. (%s)\n",
			  nt_errstr(status)));
		goto err_exit;
	}

	if (auth_resp.length) {
		status = dcerpc_push_dcerpc_auth(pkt,
						 p->auth.auth_type,
						 p->auth.auth_level,
						 0, /* pad_len */
						 p->auth.auth_context_id,
						 &auth_resp,
						 &auth_blob);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Marshalling of dcerpc_auth failed.\n"));
			goto err_exit;
		}
	}

	/* Now that we have the auth len store it into the right place in
	 * the dcerpc header */
	dcerpc_set_frag_length(&p->out_data.frag,
				p->out_data.frag.length +
				auth_blob.length);

	if (auth_resp.length) {
		if (!data_blob_append(p->mem_ctx, &p->out_data.frag,
					auth_blob.data, auth_blob.length)) {
			DEBUG(0, ("Append of auth info failed.\n"));
			goto err_exit;
		}
	}

	/*
	 * Setup the lengths for the initial reply.
	 */

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	TALLOC_FREE(auth_blob.data);
	return True;

  err_exit:

	data_blob_free(&p->out_data.frag);
	TALLOC_FREE(auth_blob.data);
	return setup_bind_nak(p, pkt);
}

static bool api_rpcTNP(struct pipes_struct *p, struct ncacn_packet *pkt,
		       const struct api_struct *api_rpc_cmds, int n_cmds,
		       const struct ndr_syntax_id *syntax);

static bool srv_pipe_check_verification_trailer(struct pipes_struct *p,
						struct ncacn_packet *pkt,
						struct pipe_rpc_fns *pipe_fns)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dcerpc_sec_verification_trailer *vt = NULL;
	const uint32_t bitmask1 =
		p->auth.client_hdr_signing ? DCERPC_SEC_VT_CLIENT_SUPPORTS_HEADER_SIGNING : 0;
	const struct dcerpc_sec_vt_pcontext pcontext = {
		.abstract_syntax = pipe_fns->syntax,
		.transfer_syntax = ndr_transfer_syntax_ndr,
	};
	const struct dcerpc_sec_vt_header2 header2 =
	       dcerpc_sec_vt_header2_from_ncacn_packet(pkt);
	struct ndr_pull *ndr;
	enum ndr_err_code ndr_err;
	bool ret = false;

	ndr = ndr_pull_init_blob(&p->in_data.data, frame);
	if (ndr == NULL) {
		goto done;
	}

	ndr_err = ndr_pop_dcerpc_sec_verification_trailer(ndr, frame, &vt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto done;
	}

	ret = dcerpc_sec_verification_trailer_check(vt, &bitmask1,
						    &pcontext, &header2);
done:
	TALLOC_FREE(frame);
	return ret;
}

/****************************************************************************
 Find the correct RPC function to call for this request.
 If the pipe is authenticated then become the correct UNIX user
 before doing the call.
****************************************************************************/

static bool api_pipe_request(struct pipes_struct *p,
				struct ncacn_packet *pkt)
{
	TALLOC_CTX *frame = talloc_stackframe();
	bool ret = False;
	struct pipe_rpc_fns *pipe_fns;
	const char *interface_name = NULL;

	if (!p->pipe_bound) {
		DEBUG(1, ("Pipe not bound!\n"));
		data_blob_free(&p->out_data.rdata);
		TALLOC_FREE(frame);
		return false;
	}

	/* get the set of RPC functions for this context */
	pipe_fns = find_pipe_fns_by_context(p->contexts,
					    pkt->u.request.context_id);
	if (pipe_fns == NULL) {
		DEBUG(0, ("No rpc function table associated with context "
			  "[%d]\n",
			  pkt->u.request.context_id));
		data_blob_free(&p->out_data.rdata);
		TALLOC_FREE(frame);
		return false;
	}

	interface_name = ndr_interface_name(&pipe_fns->syntax.uuid,
					    pipe_fns->syntax.if_version);
	SMB_ASSERT(interface_name != NULL);

	switch (p->auth.auth_level) {
	case DCERPC_AUTH_LEVEL_NONE:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PRIVACY:
		break;
	default:
		if (!pipe_fns->allow_connect) {
			char *addr;

			addr = tsocket_address_string(p->remote_address, frame);

			DEBUG(1, ("%s: restrict auth_level_connect access "
				  "to [%s] with auth[type=0x%x,level=0x%x] "
				  "on [%s] from [%s]\n",
				  __func__, interface_name,
				  p->auth.auth_type,
				  p->auth.auth_level,
				  derpc_transport_string_by_transport(p->transport),
				  addr));

			setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_ACCESS_DENIED));
			TALLOC_FREE(frame);
			return true;
		}
		break;
	}

	if (!srv_pipe_check_verification_trailer(p, pkt, pipe_fns)) {
		DEBUG(1, ("srv_pipe_check_verification_trailer: failed\n"));
		set_incoming_fault(p);
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_ACCESS_DENIED));
		data_blob_free(&p->out_data.rdata);
		TALLOC_FREE(frame);
		return true;
	}

	if (!become_authenticated_pipe_user(p->session_info)) {
		DEBUG(1, ("Failed to become pipe user!\n"));
		data_blob_free(&p->out_data.rdata);
		TALLOC_FREE(frame);
		return false;
	}

	DEBUG(5, ("Requested %s rpc service\n", interface_name));

	ret = api_rpcTNP(p, pkt, pipe_fns->cmds, pipe_fns->n_cmds,
			 &pipe_fns->syntax);
	unbecome_authenticated_pipe_user();

	TALLOC_FREE(frame);
	return ret;
}

/*******************************************************************
 Calls the underlying RPC function for a named pipe.
 ********************************************************************/

static bool api_rpcTNP(struct pipes_struct *p, struct ncacn_packet *pkt,
		       const struct api_struct *api_rpc_cmds, int n_cmds,
		       const struct ndr_syntax_id *syntax)
{
	int fn_num;
	uint32_t offset1;
	const struct ndr_interface_table *table;

	/* interpret the command */
	DEBUG(4,("api_rpcTNP: %s op 0x%x - ",
		 ndr_interface_name(&syntax->uuid, syntax->if_version),
		 pkt->u.request.opnum));

	table = ndr_table_by_uuid(&syntax->uuid);
	if (table == NULL) {
		DEBUG(0,("unknown interface\n"));
		return false;
	}

	if (DEBUGLEVEL >= 50) {
		fstring name;
		slprintf(name, sizeof(name)-1, "in_%s",
			 dcerpc_default_transport_endpoint(pkt, NCACN_NP, table));
		dump_pdu_region(name, pkt->u.request.opnum,
				&p->in_data.data, 0,
				p->in_data.data.length);
	}

	for (fn_num = 0; fn_num < n_cmds; fn_num++) {
		if (api_rpc_cmds[fn_num].opnum == pkt->u.request.opnum &&
		    api_rpc_cmds[fn_num].fn != NULL) {
			DEBUG(3, ("api_rpcTNP: rpc command: %s\n",
				  api_rpc_cmds[fn_num].name));
			break;
		}
	}

	if (fn_num == n_cmds) {
		/*
		 * For an unknown RPC just return a fault PDU but
		 * return True to allow RPC's on the pipe to continue
		 * and not put the pipe into fault state. JRA.
		 */
		DEBUG(4, ("unknown\n"));
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return True;
	}

	offset1 = p->out_data.rdata.length;

        DEBUG(6, ("api_rpc_cmds[%d].fn == %p\n", 
                fn_num, api_rpc_cmds[fn_num].fn));
	/* do the actual command */
	if(!api_rpc_cmds[fn_num].fn(p)) {
		DEBUG(0,("api_rpcTNP: %s: %s failed.\n",
			 ndr_interface_name(&syntax->uuid, syntax->if_version),
			 api_rpc_cmds[fn_num].name));
		data_blob_free(&p->out_data.rdata);
		return False;
	}

	if (p->fault_state) {
		DEBUG(4,("api_rpcTNP: fault(%d) return.\n", p->fault_state));
		setup_fault_pdu(p, NT_STATUS(p->fault_state));
		p->fault_state = 0;
		return true;
	}

	if (DEBUGLEVEL >= 50) {
		fstring name;
		slprintf(name, sizeof(name)-1, "out_%s",
			 dcerpc_default_transport_endpoint(pkt, NCACN_NP, table));
		dump_pdu_region(name, pkt->u.request.opnum,
				&p->out_data.rdata, offset1,
				p->out_data.rdata.length);
	}

	DEBUG(5,("api_rpcTNP: called %s successfully\n",
		 ndr_interface_name(&syntax->uuid, syntax->if_version)));

	/* Check for buffer underflow in rpc parsing */
	if ((DEBUGLEVEL >= 10) &&
	    (pkt->frag_length < p->in_data.data.length)) {
		DEBUG(10, ("api_rpcTNP: rpc input buffer underflow (parse error?)\n"));
		dump_data(10, p->in_data.data.data + pkt->frag_length,
			      p->in_data.data.length - pkt->frag_length);
	}

	return True;
}

/****************************************************************************
 Initialise an outgoing packet.
****************************************************************************/

static bool pipe_init_outgoing_data(struct pipes_struct *p)
{
	output_data *o_data = &p->out_data;

	/* Reset the offset counters. */
	o_data->data_sent_length = 0;
	o_data->current_pdu_sent = 0;

	data_blob_free(&o_data->frag);

	/* Free any memory in the current return data buffer. */
	data_blob_free(&o_data->rdata);

	return True;
}

/****************************************************************************
 Sets the fault state on incoming packets.
****************************************************************************/

void set_incoming_fault(struct pipes_struct *p)
{
	data_blob_free(&p->in_data.data);
	p->in_data.pdu_needed_len = 0;
	p->in_data.pdu.length = 0;
	p->fault_state = DCERPC_NCA_S_PROTO_ERROR;

	p->allow_alter = false;
	p->allow_auth3 = false;
	p->pipe_bound = false;

	DEBUG(10, ("Setting fault state\n"));
}

static NTSTATUS dcesrv_auth_request(struct pipe_auth_data *auth,
				    struct ncacn_packet *pkt,
				    DATA_BLOB *raw_pkt)
{
	NTSTATUS status;
	size_t hdr_size = DCERPC_REQUEST_LENGTH;

	DEBUG(10, ("Checking request auth.\n"));

	if (pkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		hdr_size += 16;
	}

	/* in case of sealing this function will unseal the data in place */
	status = dcerpc_check_auth(auth, pkt,
				   &pkt->u.request.stub_and_verifier,
				   hdr_size, raw_pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Processes a request pdu. This will do auth processing if needed, and
 appends the data into the complete stream if the LAST flag is not set.
****************************************************************************/

static bool process_request_pdu(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	NTSTATUS status;
	DATA_BLOB data;
	struct dcerpc_sec_vt_header2 hdr2;

	if (!p->pipe_bound) {
		DEBUG(0,("process_request_pdu: rpc request with no bind.\n"));
		set_incoming_fault(p);
		return False;
	}

	/*
	 * We don't ignore DCERPC_PFC_FLAG_PENDING_CANCEL.
	 * TODO: we can reject it with DCERPC_FAULT_NO_CALL_ACTIVE later.
	 */
	status = dcerpc_verify_ncacn_packet_header(pkt,
			DCERPC_PKT_REQUEST,
			pkt->u.request.stub_and_verifier.length,
			0, /* required_flags */
			DCERPC_PFC_FLAG_FIRST |
			DCERPC_PFC_FLAG_LAST |
			0x08 | /* this is not defined, but should be ignored */
			DCERPC_PFC_FLAG_CONC_MPX |
			DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
			DCERPC_PFC_FLAG_MAYBE |
			DCERPC_PFC_FLAG_OBJECT_UUID);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("process_request_pdu: invalid pdu: %s\n",
			  nt_errstr(status)));
		NDR_PRINT_DEBUG(ncacn_packet, pkt);
		set_incoming_fault(p);
		return false;
	}

	hdr2 = dcerpc_sec_vt_header2_from_ncacn_packet(pkt);
	if (pkt->pfc_flags & DCERPC_PFC_FLAG_FIRST) {
		p->header2 = hdr2;
	} else {
		if (!dcerpc_sec_vt_header2_equal(&hdr2, &p->header2)) {
			set_incoming_fault(p);
			return false;
		}
	}

	/* Store the opnum */
	p->opnum = pkt->u.request.opnum;

	status = dcesrv_auth_request(&p->auth, pkt, &p->in_data.pdu);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to check packet auth. (%s)\n",
			  nt_errstr(status)));
		set_incoming_fault(p);
		return false;
	}

	data = pkt->u.request.stub_and_verifier;

	/*
	 * Check the data length doesn't go over the 15Mb limit.
	 * increased after observing a bug in the Windows NT 4.0 SP6a
	 * spoolsv.exe when the response to a GETPRINTERDRIVER2 RPC
	 * will not fit in the initial buffer of size 0x1068   --jerry 22/01/2002
	 */

	if (p->in_data.data.length + data.length > MAX_RPC_DATA_SIZE) {
		DEBUG(0, ("process_request_pdu: "
			  "rpc data buffer too large (%u) + (%u)\n",
			  (unsigned int)p->in_data.data.length,
			  (unsigned int)data.length));
		set_incoming_fault(p);
		return False;
	}

	/*
	 * Append the data portion into the buffer and return.
	 */

	if (data.length) {
		if (!data_blob_append(p->mem_ctx, &p->in_data.data,
					  data.data, data.length)) {
			DEBUG(0, ("Unable to append data size %u "
				  "to parse buffer of size %u.\n",
				  (unsigned int)data.length,
				  (unsigned int)p->in_data.data.length));
			set_incoming_fault(p);
			return False;
		}
	}

	if (!(pkt->pfc_flags & DCERPC_PFC_FLAG_LAST)) {
		return true;
	}

	/*
	 * Ok - we finally have a complete RPC stream.
	 * Call the rpc command to process it.
	 */

	return api_pipe_request(p, pkt);
}

void process_complete_pdu(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	bool reply = false;

	/* Store the call_id */
	p->call_id = pkt->call_id;

	DEBUG(10, ("Processing packet type %u\n", (unsigned int)pkt->ptype));

	if (!pipe_init_outgoing_data(p)) {
		goto done;
	}

	switch (pkt->ptype) {
	case DCERPC_PKT_REQUEST:
		reply = process_request_pdu(p, pkt);
		break;

	case DCERPC_PKT_PING: /* CL request - ignore... */
		DEBUG(0, ("Error - Connectionless packet type %u received\n",
			  (unsigned int)pkt->ptype));
		break;

	case DCERPC_PKT_RESPONSE: /* No responses here. */
		DEBUG(0, ("Error - DCERPC_PKT_RESPONSE received from client"));
		break;

	case DCERPC_PKT_FAULT:
	case DCERPC_PKT_WORKING:
		/* CL request - reply to a ping when a call in process. */
	case DCERPC_PKT_NOCALL:
		/* CL - server reply to a ping call. */
	case DCERPC_PKT_REJECT:
	case DCERPC_PKT_ACK:
	case DCERPC_PKT_CL_CANCEL:
	case DCERPC_PKT_FACK:
	case DCERPC_PKT_CANCEL_ACK:
		DEBUG(0, ("Error - Connectionless packet type %u received\n",
			  (unsigned int)pkt->ptype));
		break;

	case DCERPC_PKT_BIND:
		/*
		 * We assume that a pipe bind is only in one pdu.
		 */
		reply = api_pipe_bind_req(p, pkt);
		break;

	case DCERPC_PKT_BIND_ACK:
	case DCERPC_PKT_BIND_NAK:
		DEBUG(0, ("Error - DCERPC_PKT_BINDACK/DCERPC_PKT_BINDNACK "
			  "packet type %u received.\n",
			  (unsigned int)pkt->ptype));
		break;


	case DCERPC_PKT_ALTER:
		/*
		 * We assume that a pipe bind is only in one pdu.
		 */
		reply = api_pipe_alter_context(p, pkt);
		break;

	case DCERPC_PKT_ALTER_RESP:
		DEBUG(0, ("Error - DCERPC_PKT_ALTER_RESP received: "
			  "Should only be server -> client.\n"));
		break;

	case DCERPC_PKT_AUTH3:
		/*
		 * The third packet in an auth exchange.
		 */
		reply = api_pipe_bind_auth3(p, pkt);
		break;

	case DCERPC_PKT_SHUTDOWN:
		DEBUG(0, ("Error - DCERPC_PKT_SHUTDOWN received: "
			  "Should only be server -> client.\n"));
		break;

	case DCERPC_PKT_CO_CANCEL:
		/* For now just free all client data and continue
		 * processing. */
		DEBUG(3,("process_complete_pdu: DCERPC_PKT_CO_CANCEL."
			 " Abandoning rpc call.\n"));
		/* As we never do asynchronous RPC serving, we can
		 * never cancel a call (as far as I know).
		 * If we ever did we'd have to send a cancel_ack reply.
		 * For now, just free all client data and continue
		 * processing. */
		reply = True;
		break;

#if 0
		/* Enable this if we're doing async rpc. */
		/* We must check the outstanding callid matches. */
		if (pipe_init_outgoing_data(p)) {
			/* Send a cancel_ack PDU reply. */
			/* We should probably check the auth-verifier here. */
			reply = setup_cancel_ack_reply(p, pkt);
		}
		break;
#endif

	case DCERPC_PKT_ORPHANED:
		/* We should probably check the auth-verifier here.
		 * For now just free all client data and continue
		 * processing. */
		DEBUG(3, ("process_complete_pdu: DCERPC_PKT_ORPHANED."
			  " Abandoning rpc call.\n"));
		reply = True;
		break;

	default:
		DEBUG(0, ("process_complete_pdu: "
			  "Unknown rpc type = %u received.\n",
			  (unsigned int)pkt->ptype));
		break;
	}

done:
	if (!reply) {
		DEBUG(3,("DCE/RPC fault sent!"));
		set_incoming_fault(p);
		setup_fault_pdu(p, NT_STATUS(DCERPC_NCA_S_PROTO_ERROR));
	}
	/* pkt and p->in_data.pdu.data freed by caller */
}

