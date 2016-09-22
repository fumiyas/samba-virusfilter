/*
   Unix SMB/CIFS implementation.

   [MS-RPCH] - RPC over HTTP client

   Copyright (C) 2013 Samuel Cabrero <samuelcabrero@kernevil.me>
   Copyright (C) Julien Kerihuel <j.kerihuel@openchange.org> 2013

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
#include "lib/tevent/tevent.h"
#include "lib/talloc/talloc.h"
#include "lib/tsocket/tsocket.h"
#include "lib/tls/tls.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/util_net.h"
#include "libcli/resolve/resolve.h"
#include "libcli/composite/composite.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include <gen_ndr/dcerpc.h>
#include <gen_ndr/ndr_dcerpc.h>

#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_roh.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "lib/http/http.h"

struct roh_connect_channel_state {
	struct tevent_context		*ev;
	struct tsocket_address		*local_address;
	struct tsocket_address		*remote_address;
	struct cli_credentials		*credentials;
	struct roh_connection		*roh;
	bool				tls;
	struct tstream_tls_params	*tls_params;
};

static void roh_connect_channel_in_done(struct tevent_req *);
struct tevent_req *roh_connect_channel_in_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       const char *rpcproxy_ip_address,
					       unsigned int rpcproxy_port,
					       struct cli_credentials *credentials,
					       struct roh_connection *roh,
					       bool tls,
					       struct tstream_tls_params *tls_params)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct tevent_req			*subreq;
	struct roh_connect_channel_state	*state;
	int					ret;

	DEBUG(8, ("%s: Connecting channel in socket, RPC proxy is %s:%d (TLS: %s)\n",
		  __func__, rpcproxy_ip_address, rpcproxy_port,
		  (tls ? "true" : "false")));

	req = tevent_req_create(mem_ctx, &state, struct roh_connect_channel_state);
	if (req == NULL) {
		return NULL;
	}

	if (!is_ipaddress(rpcproxy_ip_address)) {
		DEBUG(0, ("%s: Invalid host (%s), needs to be an IP address\n",
			  __func__, rpcproxy_ip_address));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->ev = ev;
	state->credentials = credentials;
	state->roh = roh;
	state->tls = tls;
	state->tls_params = tls_params;
	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0,
						&state->local_address);
	if (ret != 0) {
		DEBUG(0, ("%s: Cannot create local socket address, error: %s (%d)\n",
			  __func__, strerror(errno), errno));
		status = map_nt_error_from_unix_common(errno);
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(state, "ip",
						rpcproxy_ip_address,
						rpcproxy_port,
						&state->remote_address);
	if (ret != 0) {
		DEBUG(0, ("%s: Cannot create remote socket address, error: %s (%d)\n",
			  __func__, strerror(errno), errno));
		status = map_nt_error_from_unix_common(errno);
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	/* Initialize channel structure */
	state->roh->default_channel_in = talloc_zero(roh, struct roh_channel);
	if (tevent_req_nomem(state->roh->default_channel_in, req)) {
		return tevent_req_post(req, ev);
	}

	state->roh->default_channel_in->send_queue =
			tevent_queue_create(state->roh->default_channel_in,
					    "RoH IN virtual channel send queue");
	if (tevent_req_nomem(state->roh->default_channel_in->send_queue, req)) {
		return tevent_req_post(req, ev);
	}

	state->roh->default_channel_in->channel_cookie = GUID_random();
	subreq = tstream_inet_tcp_connect_send(state, ev, state->local_address,
					       state->remote_address);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_connect_channel_in_done, req);

	return req;
}

static void roh_connect_channel_in_tls_done(struct tevent_req *subreq);
static void roh_connect_channel_in_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_connect_channel_state	*state;
	int					ret;
	int					sys_errno;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_connect_channel_state);
	ret = tstream_inet_tcp_connect_recv(subreq, &sys_errno, state,
					    &state->roh->default_channel_in->streams.raw,
					    NULL);
	talloc_steal(state->roh->default_channel_in,
		     state->roh->default_channel_in->streams.raw);
	state->roh->default_channel_in->streams.active = state->roh->default_channel_in->streams.raw;
	TALLOC_FREE(subreq);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}

	DEBUG(8, ("%s: Socket connected\n", __func__));
	if (state->tls) {
		DEBUG(8, ("%s: Starting TLS handshake\n", __func__));
		subreq = _tstream_tls_connect_send(state,
						   state->ev,
						   state->roh->default_channel_in->streams.raw,
						   state->tls_params,
						   __location__);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, roh_connect_channel_in_tls_done, req);
		return;
	}

	tevent_req_done(req);
}

static void roh_connect_channel_in_tls_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_connect_channel_state	*state;
	int					ret;
	int					sys_errno;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_connect_channel_state);
	ret = tstream_tls_connect_recv(subreq, &sys_errno, state,
				       &state->roh->default_channel_in->streams.tls);
	talloc_steal(state->roh->default_channel_in,
		     state->roh->default_channel_in->streams.tls);
	state->roh->default_channel_in->streams.active = state->roh->default_channel_in->streams.tls;
	TALLOC_FREE(subreq);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}
	DEBUG(8, ("%s: TLS handshake completed\n", __func__));

	tevent_req_done(req);
}

NTSTATUS roh_connect_channel_in_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct roh_request_state {
	struct http_request	*request;
	struct http_request	*response;
};

static void roh_send_RPC_DATA_IN_done(struct tevent_req *subreq);
struct tevent_req *roh_send_RPC_DATA_IN_send(TALLOC_CTX *mem_ctx,
					     struct loadparm_context *lp_ctx,
					     struct tevent_context *ev,
					     struct cli_credentials *credentials,
					     struct roh_connection *roh,
					     const char *rpc_server,
					     uint32_t rpc_server_port,
					     const char *rpc_proxy,
					     bool use_ntlm)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct roh_request_state	*state;
	const char			*path;
	char				*query;
	char				*uri;

	DEBUG(8, ("%s: Sending RPC_IN_DATA request\n", __func__));

	req = tevent_req_create(mem_ctx, &state, struct roh_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->request = talloc_zero(state, struct http_request);
	if (tevent_req_nomem(state->request, req)) {
		return tevent_req_post(req, ev);
	}

	/* Build URI, as specified in section 2.2.2 */
	query = talloc_asprintf(state, "%s:%d", rpc_server, rpc_server_port);
	if (tevent_req_nomem(query, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * TODO This path changes to "/rpcwithcert/rpcproxy.dll" when using
	 * certificates
	 */
	path = "/rpc/rpcproxy.dll";
	uri = talloc_asprintf(state, "%s?%s", path, query);
	if (tevent_req_nomem(uri, req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}
	TALLOC_FREE(query);

	/*
	 * Create the HTTP channel IN request as specified in the
	 * section 2.1.2.1.1
	 */
	state->request->type = HTTP_REQ_RPC_IN_DATA;
	state->request->uri = uri;
	state->request->body.length = 0;
	state->request->body.data = NULL;
	state->request->major = '1';
	state->request->minor = '0';

	http_add_header(state, &state->request->headers,
			"Accept", "application/rpc");
	http_add_header(state, &state->request->headers,
			"User-Agent", "MSRPC");
	http_add_header(state, &state->request->headers,
			"Host", rpc_proxy);
	http_add_header(state, &state->request->headers,
			"Connection", "keep-alive");
	http_add_header(state, &state->request->headers,
			"Content-Length", "1073741824");
	http_add_header(state, &state->request->headers,
			"Cache-Control", "no-cache");
	http_add_header(state, &state->request->headers,
			"Pragma", "no-cache");

	subreq = http_send_auth_request_send(state,
					ev,
					roh->default_channel_in->streams.active,
					roh->default_channel_in->send_queue,
					state->request,
					credentials,
					lp_ctx,
					use_ntlm ? HTTP_AUTH_NTLM :
						   HTTP_AUTH_BASIC);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_send_RPC_DATA_IN_done, req);

	return req;
}

static void roh_send_RPC_DATA_IN_done(struct tevent_req *subreq)
{
	NTSTATUS		status;
	struct tevent_req	*req;

	req = tevent_req_callback_data(subreq, struct tevent_req);

	/* Receive the sent bytes to check if request has been properly sent */
	status = http_send_auth_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	DEBUG(8, ("%s: RPC_IN_DATA sent\n", __func__));

	tevent_req_done(req);
}

NTSTATUS roh_send_RPC_DATA_IN_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct roh_send_pdu_state {
	DATA_BLOB	buffer;
	struct iovec	iov;
	int		bytes_written;
	int		sys_errno;
};

static void roh_send_CONN_B1_done(struct tevent_req *subreq);
struct tevent_req *roh_send_CONN_B1_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct roh_connection *roh)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct roh_send_pdu_state	*state;
	struct dcerpc_rts		rts;
	struct ncacn_packet		pkt;
	struct ndr_push			*ndr;

	DEBUG(8, ("%s: Sending CONN/B1 request\n", __func__));

	req = tevent_req_create(mem_ctx, &state, struct roh_send_pdu_state);
	if (req == NULL) {
		return NULL;
	}

	rts.Flags = RTS_FLAG_NONE;
	rts.NumberOfCommands = 6;
	rts.Commands = talloc_array(state, struct dcerpc_rts_cmd, 6);

	/* CONN/B1: Version RTS command */
	rts.Commands[0].CommandType = 0x00000006;
	rts.Commands[0].Command.Version.Version = 0x00000001;

	/* CONN/B1: VirtualConnectionCookie RTS command */
	rts.Commands[1].CommandType = 0x00000003;
	rts.Commands[1].Command.Cookie.Cookie.Cookie = roh->connection_cookie;

	/* CONN/B1: InChannelCookie RTS command */
	rts.Commands[2].CommandType = 0x00000003;
	rts.Commands[2].Command.Cookie.Cookie.Cookie =
			roh->default_channel_in->channel_cookie;

	/* CONN/B1: ChannelLifetime */
	rts.Commands[3].CommandType = 0x00000004;
	rts.Commands[3].Command.ReceiveWindowSize.ReceiveWindowSize =
			0x40000000;

	/* CONN/B1: ClientKeepAlive */
	rts.Commands[4].CommandType = 0x00000005;
	rts.Commands[4].Command.ClientKeepalive.ClientKeepalive = 0x000493e0;

	/* CONN/B1: AssociationGroupId */
	rts.Commands[5].CommandType = 0x0000000C;
	rts.Commands[5].Command.AssociationGroupId.AssociationGroupId.Cookie =
			roh->association_group_id_cookie;

	pkt.rpc_vers = 5;
	pkt.rpc_vers_minor = 0;
	pkt.ptype = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_LAST | DCERPC_PFC_FLAG_FIRST;
	pkt.drep[0] = DCERPC_DREP_LE;
	pkt.drep[1] = 0;
	pkt.drep[2] = 0;
	pkt.drep[3] = 0;
	pkt.frag_length = 104;
	pkt.auth_length = 0;
	pkt.call_id = 0;
	pkt.u.rts = rts;

	ndr = ndr_push_init_ctx(state);
	ndr->offset = 0;
	ndr_push_ncacn_packet(ndr, NDR_SCALARS, &pkt);

	state->buffer = ndr_push_blob(ndr);
	state->iov.iov_base = (char *) state->buffer.data;
	state->iov.iov_len = state->buffer.length;

	subreq = tstream_writev_queue_send(mem_ctx,
					   ev,
					   roh->default_channel_in->streams.active,
					   roh->default_channel_in->send_queue,
					   &state->iov,
					   1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_send_CONN_B1_done, req);

	return req;
}

static void roh_send_CONN_B1_done(struct tevent_req *subreq)
{
	NTSTATUS			status;
	struct tevent_req		*req;
	struct roh_send_pdu_state	*state;
	int				sys_errno;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_send_pdu_state);

	state->bytes_written = tstream_writev_queue_recv(subreq, &sys_errno);
	state->sys_errno = sys_errno;
	TALLOC_FREE(subreq);
	if (state->bytes_written <= 0 && state->sys_errno != 0) {
		status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}
	DEBUG(8, ("%s: CONN/B1 sent (%d bytes written)\n",
		  __func__, state->bytes_written));

	tevent_req_done(req);
}

NTSTATUS roh_send_CONN_B1_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}
