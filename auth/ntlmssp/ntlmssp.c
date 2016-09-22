/*
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, client server side parsing

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2005
   Copyright (C) Stefan Metzmacher 2005

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

struct auth_session_info;

#include "includes.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "auth/ntlmssp/ntlmssp_private.h"
#include "../libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"

/**
 * Callbacks for NTLMSSP - for both client and server operating modes
 *
 */

static const struct ntlmssp_callbacks {
	enum ntlmssp_role role;
	enum ntlmssp_message_type command;
	NTSTATUS (*sync_fn)(struct gensec_security *gensec_security,
			    TALLOC_CTX *out_mem_ctx,
			    DATA_BLOB in, DATA_BLOB *out);
} ntlmssp_callbacks[] = {
	{
		.role		= NTLMSSP_CLIENT,
		.command	= NTLMSSP_INITIAL,
		.sync_fn	= ntlmssp_client_initial,
	},{
		.role		= NTLMSSP_CLIENT,
		.command	= NTLMSSP_NEGOTIATE,
		.sync_fn	= gensec_ntlmssp_resume_ccache,
	},{
		.role		= NTLMSSP_SERVER,
		.command	= NTLMSSP_NEGOTIATE,
		.sync_fn	= gensec_ntlmssp_server_negotiate,
	},{
		.role		= NTLMSSP_CLIENT,
		.command	= NTLMSSP_CHALLENGE,
		.sync_fn	= ntlmssp_client_challenge,
	},{
		.role		= NTLMSSP_SERVER,
		.command	= NTLMSSP_AUTH,
		.sync_fn	= gensec_ntlmssp_server_auth,
	}
};


static NTSTATUS gensec_ntlmssp_update_find(struct gensec_security *gensec_security,
					   struct gensec_ntlmssp_context *gensec_ntlmssp,
					   const DATA_BLOB input, uint32_t *idx)
{
	uint32_t ntlmssp_command;
	uint32_t i;

	if (gensec_ntlmssp->ntlmssp_state->expected_state == NTLMSSP_DONE) {
		/* We are strict here because other modules, which we
		 * don't fully control (such as GSSAPI) are also
		 * strict, but are tested less often */

		DEBUG(1, ("Called NTLMSSP after state machine was 'done'\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!input.length) {
		switch (gensec_ntlmssp->ntlmssp_state->role) {
		case NTLMSSP_CLIENT:
			if (gensec_ntlmssp->ntlmssp_state->resume_ccache) {
				/*
				 * make sure gensec_ntlmssp_resume_ccache()
				 * will be called
				 */
				ntlmssp_command = NTLMSSP_NEGOTIATE;
				break;
			}

			ntlmssp_command = NTLMSSP_INITIAL;
			break;
		case NTLMSSP_SERVER:
			if (gensec_security->want_features & GENSEC_FEATURE_DATAGRAM_MODE) {
				/* 'datagram' mode - no neg packet */
				ntlmssp_command = NTLMSSP_NEGOTIATE;
			} else {
				/* This is normal in SPNEGO mech negotiation fallback */
				DEBUG(2, ("Failed to parse NTLMSSP packet: zero length\n"));
				return NT_STATUS_INVALID_PARAMETER;
			}
			break;
		}
	} else {
		if (!msrpc_parse(gensec_ntlmssp->ntlmssp_state,
				 &input, "Cd",
				 "NTLMSSP",
				 &ntlmssp_command)) {
			DEBUG(1, ("Failed to parse NTLMSSP packet, could not extract NTLMSSP command\n"));
			dump_data(2, input.data, input.length);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (ntlmssp_command != gensec_ntlmssp->ntlmssp_state->expected_state) {
		DEBUG(2, ("got NTLMSSP command %u, expected %u\n", ntlmssp_command,
			  gensec_ntlmssp->ntlmssp_state->expected_state));
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i=0; i < ARRAY_SIZE(ntlmssp_callbacks); i++) {
		if (ntlmssp_callbacks[i].role == gensec_ntlmssp->ntlmssp_state->role &&
		    ntlmssp_callbacks[i].command == ntlmssp_command) {
			*idx = i;
			return NT_STATUS_OK;
		}
	}

	DEBUG(1, ("failed to find NTLMSSP callback for NTLMSSP mode %u, command %u\n",
		  gensec_ntlmssp->ntlmssp_state->role, ntlmssp_command));

	return NT_STATUS_INVALID_PARAMETER;
}

/**
 * Next state function for the wrapped NTLMSSP state machine
 *
 * @param gensec_security GENSEC state, initialised to NTLMSSP
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent,
 *                or NT_STATUS_OK if the user is authenticated.
 */

NTSTATUS gensec_ntlmssp_update(struct gensec_security *gensec_security,
			       TALLOC_CTX *out_mem_ctx,
			       struct tevent_context *ev,
			       const DATA_BLOB input, DATA_BLOB *out)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	NTSTATUS status;
	uint32_t i;

	*out = data_blob(NULL, 0);

	if (!out_mem_ctx) {
		/* if the caller doesn't want to manage/own the memory,
		   we can put it on our context */
		out_mem_ctx = ntlmssp_state;
	}

	status = gensec_ntlmssp_update_find(gensec_security, gensec_ntlmssp, input, &i);
	NT_STATUS_NOT_OK_RETURN(status);

	status = ntlmssp_callbacks[i].sync_fn(gensec_security, out_mem_ctx, input, out);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

static NTSTATUS gensec_ntlmssp_may_reset_crypto(struct gensec_security *gensec_security,
						bool full_reset)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	NTSTATUS status;
	bool reset_seqnums = full_reset;

	if (!gensec_ntlmssp_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		return NT_STATUS_OK;
	}

	status = ntlmssp_sign_reset(ntlmssp_state, reset_seqnums);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not reset NTLMSSP signing/sealing system (error was: %s)\n",
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

static const char *gensec_ntlmssp_oids[] = {
	GENSEC_OID_NTLMSSP,
	NULL
};

static const struct gensec_security_ops gensec_ntlmssp_security_ops = {
	.name		= "ntlmssp",
	.sasl_name	= GENSEC_SASL_NAME_NTLMSSP, /* "NTLM" */
	.auth_type	= DCERPC_AUTH_TYPE_NTLMSSP,
	.oid            = gensec_ntlmssp_oids,
	.client_start   = gensec_ntlmssp_client_start,
	.server_start   = gensec_ntlmssp_server_start,
	.magic 	        = gensec_ntlmssp_magic,
	.update 	= gensec_ntlmssp_update,
	.may_reset_crypto= gensec_ntlmssp_may_reset_crypto,
	.sig_size	= gensec_ntlmssp_sig_size,
	.sign_packet	= gensec_ntlmssp_sign_packet,
	.check_packet	= gensec_ntlmssp_check_packet,
	.seal_packet	= gensec_ntlmssp_seal_packet,
	.unseal_packet	= gensec_ntlmssp_unseal_packet,
	.wrap           = gensec_ntlmssp_wrap,
	.unwrap         = gensec_ntlmssp_unwrap,
	.session_key	= gensec_ntlmssp_session_key,
	.session_info   = gensec_ntlmssp_session_info,
	.have_feature   = gensec_ntlmssp_have_feature,
	.enabled        = true,
	.priority       = GENSEC_NTLMSSP
};

static const struct gensec_security_ops gensec_ntlmssp_resume_ccache_ops = {
	.name		= "ntlmssp_resume_ccache",
	.client_start   = gensec_ntlmssp_resume_ccache_start,
	.update 	= gensec_ntlmssp_update,
	.session_key	= gensec_ntlmssp_session_key,
	.have_feature   = gensec_ntlmssp_have_feature,
	.enabled        = true,
	.priority       = GENSEC_NTLMSSP
};

_PUBLIC_ NTSTATUS gensec_ntlmssp_init(void)
{
	NTSTATUS ret;

	ret = gensec_register(&gensec_ntlmssp_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_ntlmssp_security_ops.name));
		return ret;
	}

	ret = gensec_register(&gensec_ntlmssp_resume_ccache_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_ntlmssp_resume_ccache_ops.name));
		return ret;
	}

	return ret;
}

static struct gensec_security *gensec_find_child_by_ops(struct gensec_security *gensec_security,
							const struct gensec_security_ops *ops)
{
	struct gensec_security *current = gensec_security;

	while (current != NULL) {
		if (current->ops == ops) {
			return current;
		}

		current = current->child_security;
	}

	return NULL;
}

uint32_t gensec_ntlmssp_neg_flags(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp;

	gensec_security = gensec_find_child_by_ops(gensec_security,
					&gensec_ntlmssp_security_ops);
	if (gensec_security == NULL) {
		return 0;
	}

	gensec_ntlmssp = talloc_get_type_abort(gensec_security->private_data,
					       struct gensec_ntlmssp_context);
	return gensec_ntlmssp->ntlmssp_state->neg_flags;
}

const char *gensec_ntlmssp_server_domain(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp;

	gensec_security = gensec_find_child_by_ops(gensec_security,
					&gensec_ntlmssp_security_ops);
	if (gensec_security == NULL) {
		return NULL;
	}

	gensec_ntlmssp = talloc_get_type_abort(gensec_security->private_data,
					       struct gensec_ntlmssp_context);
	return gensec_ntlmssp->ntlmssp_state->server.netbios_domain;
}
