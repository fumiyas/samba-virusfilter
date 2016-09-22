/* 
   Unix SMB/CIFS implementation.

   RFC2478 Compliant SPNEGO implementation

   Copyright (C) Jim McDonough <jmcd@us.ibm.com>      2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Stefan Metzmacher <metze@samba.org>  2004-2008

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
#include "../libcli/auth/spnego.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "param/param.h"
#include "lib/util/asn1.h"
#include "lib/util/base64.h"

#undef strcasecmp

_PUBLIC_ NTSTATUS gensec_spnego_init(void);

enum spnego_state_position {
	SPNEGO_SERVER_START,
	SPNEGO_CLIENT_START,
	SPNEGO_SERVER_TARG,
	SPNEGO_CLIENT_TARG,
	SPNEGO_FALLBACK,
	SPNEGO_DONE
};

struct spnego_state {
	enum spnego_message_type expected_packet;
	enum spnego_state_position state_position;
	struct gensec_security *sub_sec_security;
	bool no_response_expected;

	const char *neg_oid;

	DATA_BLOB mech_types;
	size_t num_targs;
	bool downgraded;
	bool mic_requested;
	bool needs_mic_sign;
	bool needs_mic_check;
	bool may_skip_mic_check;
	bool done_mic_check;

	bool simulate_w2k;

	/*
	 * The following is used to implement
	 * the update token fragmentation
	 */
	size_t in_needed;
	DATA_BLOB in_frag;
	size_t out_max_length;
	DATA_BLOB out_frag;
	NTSTATUS out_status;
};


static NTSTATUS gensec_spnego_client_start(struct gensec_security *gensec_security)
{
	struct spnego_state *spnego_state;

	spnego_state = talloc_zero(gensec_security, struct spnego_state);
	if (!spnego_state) {
		return NT_STATUS_NO_MEMORY;
	}

	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
	spnego_state->state_position = SPNEGO_CLIENT_START;
	spnego_state->sub_sec_security = NULL;
	spnego_state->no_response_expected = false;
	spnego_state->mech_types = data_blob(NULL, 0);
	spnego_state->out_max_length = gensec_max_update_size(gensec_security);
	spnego_state->out_status = NT_STATUS_MORE_PROCESSING_REQUIRED;

	spnego_state->simulate_w2k = gensec_setting_bool(gensec_security->settings,
						"spnego", "simulate_w2k", false);

	gensec_security->private_data = spnego_state;
	return NT_STATUS_OK;
}

static NTSTATUS gensec_spnego_server_start(struct gensec_security *gensec_security)
{
	struct spnego_state *spnego_state;

	spnego_state = talloc_zero(gensec_security, struct spnego_state);
	if (!spnego_state) {
		return NT_STATUS_NO_MEMORY;
	}

	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
	spnego_state->state_position = SPNEGO_SERVER_START;
	spnego_state->sub_sec_security = NULL;
	spnego_state->no_response_expected = false;
	spnego_state->mech_types = data_blob(NULL, 0);
	spnego_state->out_max_length = gensec_max_update_size(gensec_security);
	spnego_state->out_status = NT_STATUS_MORE_PROCESSING_REQUIRED;

	spnego_state->simulate_w2k = gensec_setting_bool(gensec_security->settings,
						"spnego", "simulate_w2k", false);

	gensec_security->private_data = spnego_state;
	return NT_STATUS_OK;
}

/*
  wrappers for the spnego_*() functions
*/
static NTSTATUS gensec_spnego_unseal_packet(struct gensec_security *gensec_security, 
					    uint8_t *data, size_t length, 
					    const uint8_t *whole_pdu, size_t pdu_length, 
					    const DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_unseal_packet(spnego_state->sub_sec_security, 
				    data, length, 
				    whole_pdu, pdu_length,
				    sig); 
}

static NTSTATUS gensec_spnego_check_packet(struct gensec_security *gensec_security, 
					   const uint8_t *data, size_t length, 
					   const uint8_t *whole_pdu, size_t pdu_length, 
					   const DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_check_packet(spnego_state->sub_sec_security, 
				   data, length, 
				   whole_pdu, pdu_length,
				   sig);
}

static NTSTATUS gensec_spnego_seal_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_seal_packet(spnego_state->sub_sec_security, 
				  mem_ctx, 
				  data, length, 
				  whole_pdu, pdu_length,
				  sig);
}

static NTSTATUS gensec_spnego_sign_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  const uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_sign_packet(spnego_state->sub_sec_security, 
				  mem_ctx, 
				  data, length, 
				  whole_pdu, pdu_length,
				  sig);
}

static NTSTATUS gensec_spnego_wrap(struct gensec_security *gensec_security, 
				   TALLOC_CTX *mem_ctx, 
				   const DATA_BLOB *in, 
				   DATA_BLOB *out)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		DEBUG(1, ("gensec_spnego_wrap: wrong state for wrap\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_wrap(spnego_state->sub_sec_security, 
			   mem_ctx, in, out);
}

static NTSTATUS gensec_spnego_unwrap(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     const DATA_BLOB *in, 
				     DATA_BLOB *out)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		DEBUG(1, ("gensec_spnego_unwrap: wrong state for unwrap\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_unwrap(spnego_state->sub_sec_security, 
			     mem_ctx, in, out);
}

static size_t gensec_spnego_sig_size(struct gensec_security *gensec_security, size_t data_size) 
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return 0;
	}

	return gensec_sig_size(spnego_state->sub_sec_security, data_size);
}

static size_t gensec_spnego_max_input_size(struct gensec_security *gensec_security) 
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return 0;
	}

	return gensec_max_input_size(spnego_state->sub_sec_security);
}

static size_t gensec_spnego_max_wrapped_size(struct gensec_security *gensec_security) 
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return 0;
	}

	return gensec_max_wrapped_size(spnego_state->sub_sec_security);
}

static NTSTATUS gensec_spnego_session_key(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx,
					  DATA_BLOB *session_key)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
	if (!spnego_state->sub_sec_security) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_session_key(spnego_state->sub_sec_security, 
				  mem_ctx,
				  session_key);
}

static NTSTATUS gensec_spnego_session_info(struct gensec_security *gensec_security,
					   TALLOC_CTX *mem_ctx,
					   struct auth_session_info **session_info)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
	if (!spnego_state->sub_sec_security) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_session_info(spnego_state->sub_sec_security, 
				   mem_ctx,
				   session_info);
}

/** Fallback to another GENSEC mechanism, based on magic strings 
 *
 * This is the 'fallback' case, where we don't get SPNEGO, and have to
 * try all the other options (and hope they all have a magic string
 * they check)
*/

static NTSTATUS gensec_spnego_server_try_fallback(struct gensec_security *gensec_security, 
						  struct spnego_state *spnego_state,
						  struct tevent_context *ev,
						  TALLOC_CTX *out_mem_ctx, 
						  const DATA_BLOB in, DATA_BLOB *out) 
{
	int i,j;
	const struct gensec_security_ops **all_ops;

	all_ops = gensec_security_mechs(gensec_security, out_mem_ctx);

	for (i=0; all_ops && all_ops[i]; i++) {
		bool is_spnego;
		NTSTATUS nt_status;

	    	if (gensec_security != NULL && 
				!gensec_security_ops_enabled(all_ops[i], gensec_security))
		    continue;

		if (!all_ops[i]->oid) {
			continue;
		}

		is_spnego = false;
		for (j=0; all_ops[i]->oid[j]; j++) {
			if (strcasecmp(GENSEC_OID_SPNEGO,all_ops[i]->oid[j]) == 0) {
				is_spnego = true;
			}
		}
		if (is_spnego) {
			continue;
		}

		if (!all_ops[i]->magic) {
			continue;
		}

		nt_status = all_ops[i]->magic(gensec_security, &in);
		if (!NT_STATUS_IS_OK(nt_status)) {
			continue;
		}

		spnego_state->state_position = SPNEGO_FALLBACK;

		nt_status = gensec_subcontext_start(spnego_state, 
						    gensec_security, 
						    &spnego_state->sub_sec_security);

		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		/* select the sub context */
		nt_status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						     all_ops[i]);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		nt_status = gensec_update_ev(spnego_state->sub_sec_security,
					  ev, out_mem_ctx, in, out);
		return nt_status;
	}
	DEBUG(1, ("Failed to parse SPNEGO request\n"));
	return NT_STATUS_INVALID_PARAMETER;
}

/* 
   Parse the netTokenInit, either from the client, to the server, or
   from the server to the client.
*/

static NTSTATUS gensec_spnego_parse_negTokenInit(struct gensec_security *gensec_security,
						 struct spnego_state *spnego_state, 
						 TALLOC_CTX *out_mem_ctx, 
						 struct tevent_context *ev,
						 const char * const *mechType,
						 const DATA_BLOB unwrapped_in, DATA_BLOB *unwrapped_out) 
{
	int i;
	NTSTATUS nt_status = NT_STATUS_INVALID_PARAMETER;
	DATA_BLOB null_data_blob = data_blob(NULL,0);
	bool ok;

	const struct gensec_security_ops_wrapper *all_sec
		= gensec_security_by_oid_list(gensec_security, 
					      out_mem_ctx, 
					      mechType,
					      GENSEC_OID_SPNEGO);

	ok = spnego_write_mech_types(spnego_state,
				     mechType,
				     &spnego_state->mech_types);
	if (!ok) {
		DEBUG(1, ("SPNEGO: Failed to write mechTypes\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (spnego_state->state_position == SPNEGO_SERVER_START) {
		uint32_t j;
		for (j=0; mechType && mechType[j]; j++) {
			for (i=0; all_sec && all_sec[i].op; i++) {
				if (strcmp(mechType[j], all_sec[i].oid) != 0) {
					continue;
				}

				nt_status = gensec_subcontext_start(spnego_state,
								    gensec_security,
								    &spnego_state->sub_sec_security);
				if (!NT_STATUS_IS_OK(nt_status)) {
					return nt_status;
				}
				/* select the sub context */
				nt_status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
								     all_sec[i].op);
				if (!NT_STATUS_IS_OK(nt_status)) {
					talloc_free(spnego_state->sub_sec_security);
					spnego_state->sub_sec_security = NULL;
					break;
				}

				if (j > 0) {
					/* no optimistic token */
					spnego_state->neg_oid = all_sec[i].oid;
					*unwrapped_out = data_blob_null;
					nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
					/*
					 * Indicate the downgrade and request a
					 * mic.
					 */
					spnego_state->downgraded = true;
					spnego_state->mic_requested = true;
					break;
				}

				nt_status = gensec_update_ev(spnego_state->sub_sec_security,
							  out_mem_ctx, 
							  ev,
							  unwrapped_in,
							  unwrapped_out);
				if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_PARAMETER) || 
				    NT_STATUS_EQUAL(nt_status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO)) {
					/* Pretend we never started it (lets the first run find some incompatible demand) */

					DEBUG(1, ("SPNEGO(%s) NEG_TOKEN_INIT failed to parse contents: %s\n", 
						  spnego_state->sub_sec_security->ops->name, nt_errstr(nt_status)));
					talloc_free(spnego_state->sub_sec_security);
					spnego_state->sub_sec_security = NULL;
					break;
				}

				spnego_state->neg_oid = all_sec[i].oid;
				break;
			}
			if (spnego_state->sub_sec_security) {
				break;
			}
		}

		if (!spnego_state->sub_sec_security) {
			DEBUG(1, ("SPNEGO: Could not find a suitable mechtype in NEG_TOKEN_INIT\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	/* Having tried any optimistic token from the client (if we
	 * were the server), if we didn't get anywhere, walk our list
	 * in our preference order */

	if (!spnego_state->sub_sec_security) {
		for (i=0; all_sec && all_sec[i].op; i++) {
			nt_status = gensec_subcontext_start(spnego_state,
							    gensec_security,
							    &spnego_state->sub_sec_security);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}
			/* select the sub context */
			nt_status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
							     all_sec[i].op);
			if (!NT_STATUS_IS_OK(nt_status)) {
				talloc_free(spnego_state->sub_sec_security);
				spnego_state->sub_sec_security = NULL;
				continue;
			}

			spnego_state->neg_oid = all_sec[i].oid;

			/* only get the helping start blob for the first OID */
			nt_status = gensec_update_ev(spnego_state->sub_sec_security,
						  out_mem_ctx, 
						  ev,
						  null_data_blob, 
						  unwrapped_out);

			/* it is likely that a NULL input token will
			 * not be liked by most server mechs, but if
			 * we are in the client, we want the first
			 * update packet to be able to abort the use
			 * of this mech */
			if (spnego_state->state_position != SPNEGO_SERVER_START) {
				if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_PARAMETER) || 
				    NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_LOGON_SERVERS) ||
				    NT_STATUS_EQUAL(nt_status, NT_STATUS_TIME_DIFFERENCE_AT_DC) ||
				    NT_STATUS_EQUAL(nt_status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO)) {
					/* Pretend we never started it (lets the first run find some incompatible demand) */

					DEBUG(3, ("SPNEGO(%s) NEG_TOKEN_INIT failed: %s\n",
						  spnego_state->sub_sec_security->ops->name, nt_errstr(nt_status)));
					talloc_free(spnego_state->sub_sec_security);
					spnego_state->sub_sec_security = NULL;
					continue;
				}
			}

			break;
		}
	}

	if (spnego_state->sub_sec_security) {
		/* it is likely that a NULL input token will
		 * not be liked by most server mechs, but this
		 * does the right thing in the CIFS client.
		 * just push us along the merry-go-round
		 * again, and hope for better luck next
		 * time */

		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_PARAMETER)) {
			*unwrapped_out = data_blob(NULL, 0);
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		}

		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_PARAMETER) 
		    && !NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED) 
		    && !NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("SPNEGO(%s) NEG_TOKEN_INIT failed: %s\n", 
				  spnego_state->sub_sec_security->ops->name, nt_errstr(nt_status)));
			talloc_free(spnego_state->sub_sec_security);
			spnego_state->sub_sec_security = NULL;

			/* We started the mech correctly, and the
			 * input from the other side was valid.
			 * Return the error (say bad password, invalid
			 * ticket) */
			return nt_status;
		}

		return nt_status; /* OK, INVALID_PARAMETER ore MORE PROCESSING */
	}

	DEBUG(1, ("SPNEGO: Could not find a suitable mechtype in NEG_TOKEN_INIT\n"));
	/* we could re-negotiate here, but it would only work
	 * if the client or server lied about what it could
	 * support the first time.  Lets keep this code to
	 * reality */

	return nt_status;
}

/** create a negTokenInit 
 *
 * This is the same packet, no matter if the client or server sends it first, but it is always the first packet
*/
static NTSTATUS gensec_spnego_create_negTokenInit(struct gensec_security *gensec_security, 
						  struct spnego_state *spnego_state,
						  TALLOC_CTX *out_mem_ctx, 
						  struct tevent_context *ev,
						  const DATA_BLOB in, DATA_BLOB *out) 
{
	int i;
	NTSTATUS nt_status = NT_STATUS_INVALID_PARAMETER;
	DATA_BLOB null_data_blob = data_blob(NULL,0);
	const char **mechTypes = NULL;
	DATA_BLOB unwrapped_out = data_blob(NULL, 0);
	const struct gensec_security_ops_wrapper *all_sec;

	mechTypes = gensec_security_oids(gensec_security, 
					 out_mem_ctx, GENSEC_OID_SPNEGO);

	all_sec	= gensec_security_by_oid_list(gensec_security, 
					      out_mem_ctx, 
					      mechTypes,
					      GENSEC_OID_SPNEGO);
	for (i=0; all_sec && all_sec[i].op; i++) {
		struct spnego_data spnego_out;
		const char **send_mech_types;
		bool ok;

		nt_status = gensec_subcontext_start(spnego_state,
						    gensec_security,
						    &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		/* select the sub context */
		nt_status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						     all_sec[i].op);
		if (!NT_STATUS_IS_OK(nt_status)) {
			talloc_free(spnego_state->sub_sec_security);
			spnego_state->sub_sec_security = NULL;
			continue;
		}

		/* In the client, try and produce the first (optimistic) packet */
		if (spnego_state->state_position == SPNEGO_CLIENT_START) {
			nt_status = gensec_update_ev(spnego_state->sub_sec_security,
						  out_mem_ctx, 
						  ev,
						  null_data_blob,
						  &unwrapped_out);

			if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED) 
			    && !NT_STATUS_IS_OK(nt_status)) {
				DEBUG(1, ("SPNEGO(%s) creating NEG_TOKEN_INIT failed: %s\n", 
					  spnego_state->sub_sec_security->ops->name, nt_errstr(nt_status)));
				talloc_free(spnego_state->sub_sec_security);
				spnego_state->sub_sec_security = NULL;
				/* Pretend we never started it (lets the first run find some incompatible demand) */

				continue;
			}
		}

		spnego_out.type = SPNEGO_NEG_TOKEN_INIT;

		send_mech_types = gensec_security_oids_from_ops_wrapped(out_mem_ctx,
									&all_sec[i]);

		ok = spnego_write_mech_types(spnego_state,
					     send_mech_types,
					     &spnego_state->mech_types);
		if (!ok) {
			DEBUG(1, ("SPNEGO: Failed to write mechTypes\n"));
			return NT_STATUS_NO_MEMORY;
		}

		/* List the remaining mechs as options */
		spnego_out.negTokenInit.mechTypes = send_mech_types;
		spnego_out.negTokenInit.reqFlags = null_data_blob;
		spnego_out.negTokenInit.reqFlagsPadding = 0;

		if (spnego_state->state_position == SPNEGO_SERVER_START) {
			spnego_out.negTokenInit.mechListMIC
				= data_blob_string_const(ADS_IGNORE_PRINCIPAL);
		} else {
			spnego_out.negTokenInit.mechListMIC = null_data_blob;
		}

		spnego_out.negTokenInit.mechToken = unwrapped_out;

		if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
			DEBUG(1, ("Failed to write NEG_TOKEN_INIT\n"));
				return NT_STATUS_INVALID_PARAMETER;
		}

		/* set next state */
		spnego_state->neg_oid = all_sec[i].oid;

		if (NT_STATUS_IS_OK(nt_status)) {
			spnego_state->no_response_expected = true;
		}

		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	} 
	talloc_free(spnego_state->sub_sec_security);
	spnego_state->sub_sec_security = NULL;

	DEBUG(10, ("Failed to setup SPNEGO negTokenInit request: %s\n", nt_errstr(nt_status)));
	return nt_status;
}


/** create a server negTokenTarg 
 *
 * This is the case, where the client is the first one who sends data
*/

static NTSTATUS gensec_spnego_server_negTokenTarg(struct spnego_state *spnego_state,
						  TALLOC_CTX *out_mem_ctx, 
						  NTSTATUS nt_status,
						  const DATA_BLOB unwrapped_out,
						  DATA_BLOB mech_list_mic,
						  DATA_BLOB *out)
{
	struct spnego_data spnego_out;
	DATA_BLOB null_data_blob = data_blob(NULL, 0);

	/* compose reply */
	spnego_out.type = SPNEGO_NEG_TOKEN_TARG;
	spnego_out.negTokenTarg.responseToken = unwrapped_out;
	spnego_out.negTokenTarg.mechListMIC = mech_list_mic;
	spnego_out.negTokenTarg.supportedMech = NULL;

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {	
		spnego_out.negTokenTarg.supportedMech = spnego_state->neg_oid;
		if (spnego_state->mic_requested) {
			spnego_out.negTokenTarg.negResult = SPNEGO_REQUEST_MIC;
			spnego_state->mic_requested = false;
		} else {
			spnego_out.negTokenTarg.negResult = SPNEGO_ACCEPT_INCOMPLETE;
		}
		spnego_state->state_position = SPNEGO_SERVER_TARG;
	} else if (NT_STATUS_IS_OK(nt_status)) {
		if (unwrapped_out.data) {
			spnego_out.negTokenTarg.supportedMech = spnego_state->neg_oid;
		}
		spnego_out.negTokenTarg.negResult = SPNEGO_ACCEPT_COMPLETED;
		spnego_state->state_position = SPNEGO_DONE;
	} else {
		spnego_out.negTokenTarg.negResult = SPNEGO_REJECT;
		spnego_out.negTokenTarg.mechListMIC = null_data_blob;
		DEBUG(2, ("SPNEGO login failed: %s\n", nt_errstr(nt_status)));
		spnego_state->state_position = SPNEGO_DONE;
	}

	if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
		DEBUG(1, ("Failed to write SPNEGO reply to NEG_TOKEN_TARG\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
	spnego_state->num_targs++;

	return nt_status;
}


static NTSTATUS gensec_spnego_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx, 
				     struct tevent_context *ev,
				     const DATA_BLOB in, DATA_BLOB *out) 
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
	DATA_BLOB null_data_blob = data_blob(NULL, 0);
	DATA_BLOB mech_list_mic = data_blob(NULL, 0);
	DATA_BLOB unwrapped_out = data_blob(NULL, 0);
	struct spnego_data spnego_out;
	struct spnego_data spnego;

	ssize_t len;

	*out = data_blob(NULL, 0);

	if (!out_mem_ctx) {
		out_mem_ctx = spnego_state;
	}

	/* and switch into the state machine */

	switch (spnego_state->state_position) {
	case SPNEGO_FALLBACK:
		return gensec_update_ev(spnego_state->sub_sec_security, ev,
				     out_mem_ctx, in, out);
	case SPNEGO_SERVER_START:
	{
		NTSTATUS nt_status;
		if (in.length) {

			len = spnego_read_data(gensec_security, in, &spnego);
			if (len == -1) {
				return gensec_spnego_server_try_fallback(gensec_security, spnego_state,
									 ev, out_mem_ctx, in, out);
			}
			/* client sent NegTargetInit, we send NegTokenTarg */

			/* OK, so it's real SPNEGO, check the packet's the one we expect */
			if (spnego.type != spnego_state->expected_packet) {
				DEBUG(1, ("Invalid SPNEGO request: %d, expected %d\n", spnego.type, 
					  spnego_state->expected_packet));
				dump_data(1, in.data, in.length);
				spnego_free_data(&spnego);
				return NT_STATUS_INVALID_PARAMETER;
			}

			nt_status = gensec_spnego_parse_negTokenInit(gensec_security,
								     spnego_state,
								     out_mem_ctx, 
								     ev,
								     spnego.negTokenInit.mechTypes,
								     spnego.negTokenInit.mechToken, 
								     &unwrapped_out);

			if (spnego_state->simulate_w2k) {
				/*
				 * Windows 2000 returns the unwrapped token
				 * also in the mech_list_mic field.
				 *
				 * In order to verify our client code,
				 * we need a way to have a server with this
				 * broken behaviour
				 */
				mech_list_mic = unwrapped_out;
			}

			nt_status = gensec_spnego_server_negTokenTarg(spnego_state,
								      out_mem_ctx,
								      nt_status,
								      unwrapped_out,
								      mech_list_mic,
								      out);

			spnego_free_data(&spnego);

			return nt_status;
		} else {
			nt_status = gensec_spnego_create_negTokenInit(gensec_security, spnego_state, 
								      out_mem_ctx, ev, in, out);
			spnego_state->state_position = SPNEGO_SERVER_START;
			spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
			return nt_status;
		}
	}

	case SPNEGO_CLIENT_START:
	{
		/* The server offers a list of mechanisms */

		const char *my_mechs[] = {NULL, NULL};
		NTSTATUS nt_status = NT_STATUS_INVALID_PARAMETER;
		bool ok;

		if (!in.length) {
			/* client to produce negTokenInit */
			nt_status = gensec_spnego_create_negTokenInit(gensec_security, spnego_state, 
								      out_mem_ctx, ev, in, out);
			spnego_state->state_position = SPNEGO_CLIENT_TARG;
			spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
			return nt_status;
		}

		len = spnego_read_data(gensec_security, in, &spnego);

		if (len == -1) {
			DEBUG(1, ("Invalid SPNEGO request:\n"));
			dump_data(1, in.data, in.length);
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* OK, so it's real SPNEGO, check the packet's the one we expect */
		if (spnego.type != spnego_state->expected_packet) {
			DEBUG(1, ("Invalid SPNEGO request: %d, expected %d\n", spnego.type, 
				  spnego_state->expected_packet));
			dump_data(1, in.data, in.length);
			spnego_free_data(&spnego);
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (spnego.negTokenInit.targetPrincipal
		    && strcmp(spnego.negTokenInit.targetPrincipal, ADS_IGNORE_PRINCIPAL) != 0) {
			DEBUG(5, ("Server claims it's principal name is %s\n", spnego.negTokenInit.targetPrincipal));
			if (lpcfg_client_use_spnego_principal(gensec_security->settings->lp_ctx)) {
				gensec_set_target_principal(gensec_security, spnego.negTokenInit.targetPrincipal);
			}
		}

		nt_status = gensec_spnego_parse_negTokenInit(gensec_security,
							     spnego_state,
							     out_mem_ctx, 
							     ev,
							     spnego.negTokenInit.mechTypes,
							     spnego.negTokenInit.mechToken, 
							     &unwrapped_out);

		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(nt_status)) {
			spnego_free_data(&spnego);
			return nt_status;
		}

		my_mechs[0] = spnego_state->neg_oid;
		/* compose reply */
		spnego_out.type = SPNEGO_NEG_TOKEN_INIT;
		spnego_out.negTokenInit.mechTypes = my_mechs;
		spnego_out.negTokenInit.reqFlags = null_data_blob;
		spnego_out.negTokenInit.reqFlagsPadding = 0;
		spnego_out.negTokenInit.mechListMIC = null_data_blob;
		spnego_out.negTokenInit.mechToken = unwrapped_out;

		if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
			DEBUG(1, ("Failed to write SPNEGO reply to NEG_TOKEN_INIT\n"));
				return NT_STATUS_INVALID_PARAMETER;
		}

		ok = spnego_write_mech_types(spnego_state,
					     my_mechs,
					     &spnego_state->mech_types);
		if (!ok) {
			DEBUG(1, ("SPNEGO: Failed to write mechTypes\n"));
			return NT_STATUS_NO_MEMORY;
		}

		/* set next state */
		spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
		spnego_state->state_position = SPNEGO_CLIENT_TARG;

		if (NT_STATUS_IS_OK(nt_status)) {
			spnego_state->no_response_expected = true;
		}

		spnego_free_data(&spnego);
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}
	case SPNEGO_SERVER_TARG:
	{
		NTSTATUS nt_status;
		bool have_sign = true;
		bool new_spnego = false;

		if (!in.length) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		len = spnego_read_data(gensec_security, in, &spnego);

		if (len == -1) {
			DEBUG(1, ("Invalid SPNEGO request:\n"));
			dump_data(1, in.data, in.length);
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* OK, so it's real SPNEGO, check the packet's the one we expect */
		if (spnego.type != spnego_state->expected_packet) {
			DEBUG(1, ("Invalid SPNEGO request: %d, expected %d\n", spnego.type, 
				  spnego_state->expected_packet));
			dump_data(1, in.data, in.length);
			spnego_free_data(&spnego);
			return NT_STATUS_INVALID_PARAMETER;
		}

		spnego_state->num_targs++;

		if (!spnego_state->sub_sec_security) {
			DEBUG(1, ("SPNEGO: Did not setup a mech in NEG_TOKEN_INIT\n"));
			spnego_free_data(&spnego);
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (spnego_state->needs_mic_check) {
			if (spnego.negTokenTarg.responseToken.length != 0) {
				DEBUG(1, ("SPNEGO: Did not setup a mech in NEG_TOKEN_INIT\n"));
				spnego_free_data(&spnego);
				return NT_STATUS_INVALID_PARAMETER;
			}

			nt_status = gensec_check_packet(spnego_state->sub_sec_security,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							&spnego.negTokenTarg.mechListMIC);
			if (NT_STATUS_IS_OK(nt_status)) {
				spnego_state->needs_mic_check = false;
				spnego_state->done_mic_check = true;
			} else {
				DEBUG(2,("GENSEC SPNEGO: failed to verify mechListMIC: %s\n",
					nt_errstr(nt_status)));
			}
			goto server_response;
		}

		nt_status = gensec_update_ev(spnego_state->sub_sec_security,
					     out_mem_ctx, ev,
					     spnego.negTokenTarg.responseToken,
					     &unwrapped_out);
		if (!NT_STATUS_IS_OK(nt_status)) {
			goto server_response;
		}

		have_sign = gensec_have_feature(spnego_state->sub_sec_security,
						GENSEC_FEATURE_SIGN);
		if (spnego_state->simulate_w2k) {
			have_sign = false;
		}
		new_spnego = gensec_have_feature(spnego_state->sub_sec_security,
						 GENSEC_FEATURE_NEW_SPNEGO);
		if (spnego.negTokenTarg.mechListMIC.length > 0) {
			new_spnego = true;
		}

		if (have_sign && new_spnego) {
			spnego_state->needs_mic_check = true;
			spnego_state->needs_mic_sign = true;
		}

		if (have_sign && spnego.negTokenTarg.mechListMIC.length > 0) {
			nt_status = gensec_check_packet(spnego_state->sub_sec_security,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							&spnego.negTokenTarg.mechListMIC);
			if (!NT_STATUS_IS_OK(nt_status)) {
				DEBUG(2,("GENSEC SPNEGO: failed to verify mechListMIC: %s\n",
					nt_errstr(nt_status)));
				goto server_response;
			}

			spnego_state->needs_mic_check = false;
			spnego_state->done_mic_check = true;
		}

		if (spnego_state->needs_mic_sign) {
			nt_status = gensec_sign_packet(spnego_state->sub_sec_security,
						       out_mem_ctx,
						       spnego_state->mech_types.data,
						       spnego_state->mech_types.length,
						       spnego_state->mech_types.data,
						       spnego_state->mech_types.length,
						       &mech_list_mic);
			if (!NT_STATUS_IS_OK(nt_status)) {
				DEBUG(2,("GENSEC SPNEGO: failed to sign mechListMIC: %s\n",
					nt_errstr(nt_status)));
				goto server_response;
			}
			spnego_state->needs_mic_sign = false;
		}

		if (spnego_state->needs_mic_check) {
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		}

 server_response:
		nt_status = gensec_spnego_server_negTokenTarg(spnego_state,
							      out_mem_ctx, 
							      nt_status,
							      unwrapped_out,
							      mech_list_mic,
							      out);

		spnego_free_data(&spnego);

		return nt_status;
	}
	case SPNEGO_CLIENT_TARG:
	{
		NTSTATUS nt_status = NT_STATUS_INTERNAL_ERROR;

		if (!in.length) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		len = spnego_read_data(gensec_security, in, &spnego);

		if (len == -1) {
			DEBUG(1, ("Invalid SPNEGO request:\n"));
			dump_data(1, in.data, in.length);
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* OK, so it's real SPNEGO, check the packet's the one we expect */
		if (spnego.type != spnego_state->expected_packet) {
			DEBUG(1, ("Invalid SPNEGO request: %d, expected %d\n", spnego.type, 
				  spnego_state->expected_packet));
			dump_data(1, in.data, in.length);
			spnego_free_data(&spnego);
			return NT_STATUS_INVALID_PARAMETER;
		}

		spnego_state->num_targs++;

		if (spnego.negTokenTarg.negResult == SPNEGO_REJECT) {
			spnego_free_data(&spnego);
			return NT_STATUS_LOGON_FAILURE;
		}

		if (spnego.negTokenTarg.negResult == SPNEGO_REQUEST_MIC) {
			spnego_state->mic_requested = true;
		}

		/* Server didn't like our choice of mech, and chose something else */
		if (((spnego.negTokenTarg.negResult == SPNEGO_ACCEPT_INCOMPLETE) ||
		     (spnego.negTokenTarg.negResult == SPNEGO_REQUEST_MIC)) &&
		    spnego.negTokenTarg.supportedMech &&
		    strcmp(spnego.negTokenTarg.supportedMech, spnego_state->neg_oid) != 0) {
			DEBUG(3,("GENSEC SPNEGO: client preferred mech (%s) not accepted, server wants: %s\n",
				 gensec_get_name_by_oid(gensec_security, spnego_state->neg_oid),
				 gensec_get_name_by_oid(gensec_security, spnego.negTokenTarg.supportedMech)));
			spnego_state->downgraded = true;
			spnego_state->no_response_expected = false;
			talloc_free(spnego_state->sub_sec_security);
			nt_status = gensec_subcontext_start(spnego_state,
							    gensec_security,
							    &spnego_state->sub_sec_security);
			if (!NT_STATUS_IS_OK(nt_status)) {
				spnego_free_data(&spnego);
				return nt_status;
			}
			/* select the sub context */
			nt_status = gensec_start_mech_by_oid(spnego_state->sub_sec_security,
							     spnego.negTokenTarg.supportedMech);
			if (!NT_STATUS_IS_OK(nt_status)) {
				spnego_free_data(&spnego);
				return nt_status;
			}

			spnego_state->neg_oid = talloc_strdup(spnego_state,
						spnego.negTokenTarg.supportedMech);
			if (spnego_state->neg_oid == NULL) {
				spnego_free_data(&spnego);
				return NT_STATUS_NO_MEMORY;
			};
		}

		if (spnego.negTokenTarg.mechListMIC.length > 0) {
			DATA_BLOB *m = &spnego.negTokenTarg.mechListMIC;
			const DATA_BLOB *r = &spnego.negTokenTarg.responseToken;

			/*
			 * Windows 2000 has a bug, it repeats the
			 * responseToken in the mechListMIC field.
			 */
			if (m->length == r->length) {
				int cmp;

				cmp = memcmp(m->data, r->data, m->length);
				if (cmp == 0) {
					data_blob_free(m);
				}
			}
		}

		if (spnego.negTokenTarg.mechListMIC.length > 0) {
			if (spnego_state->no_response_expected) {
				spnego_state->needs_mic_check = true;
			}
		}

		if (spnego_state->needs_mic_check) {
			if (spnego.negTokenTarg.responseToken.length != 0) {
				DEBUG(1, ("SPNEGO: Did not setup a mech in NEG_TOKEN_INIT\n"));
				spnego_free_data(&spnego);
				return NT_STATUS_INVALID_PARAMETER;
			}

			if (spnego.negTokenTarg.mechListMIC.length == 0
			    && spnego_state->may_skip_mic_check) {
				/*
				 * In this case we don't require
				 * a mechListMIC from the server.
				 *
				 * This works around bugs in the Azure
				 * and Apple spnego implementations.
				 *
				 * See
				 * https://bugzilla.samba.org/show_bug.cgi?id=11994
				 */
				spnego_state->needs_mic_check = false;
				nt_status = NT_STATUS_OK;
				goto client_response;
			}

			nt_status = gensec_check_packet(spnego_state->sub_sec_security,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							&spnego.negTokenTarg.mechListMIC);
			if (!NT_STATUS_IS_OK(nt_status)) {
				DEBUG(2,("GENSEC SPNEGO: failed to verify mechListMIC: %s\n",
					nt_errstr(nt_status)));
				spnego_free_data(&spnego);
				return nt_status;
			}
			spnego_state->needs_mic_check = false;
			spnego_state->done_mic_check = true;
			goto client_response;
		}

		if (!spnego_state->no_response_expected) {
			nt_status = gensec_update_ev(spnego_state->sub_sec_security,
						  out_mem_ctx, ev,
						  spnego.negTokenTarg.responseToken, 
						  &unwrapped_out);
			if (!NT_STATUS_IS_OK(nt_status)) {
				goto client_response;
			}

			spnego_state->no_response_expected = true;
		} else {
			nt_status = NT_STATUS_OK;
		}

		if (spnego_state->no_response_expected &&
		    !spnego_state->done_mic_check)
		{
			bool have_sign = true;
			bool new_spnego = false;

			have_sign = gensec_have_feature(spnego_state->sub_sec_security,
							GENSEC_FEATURE_SIGN);
			if (spnego_state->simulate_w2k) {
				have_sign = false;
			}
			new_spnego = gensec_have_feature(spnego_state->sub_sec_security,
							 GENSEC_FEATURE_NEW_SPNEGO);

			switch (spnego.negTokenTarg.negResult) {
			case SPNEGO_ACCEPT_COMPLETED:
			case SPNEGO_NONE_RESULT:
				if (spnego_state->num_targs == 1) {
					/*
					 * the first exchange doesn't require
					 * verification
					 */
					new_spnego = false;
				}

				break;

			case SPNEGO_ACCEPT_INCOMPLETE:
				if (spnego.negTokenTarg.mechListMIC.length > 0) {
					new_spnego = true;
					break;
				}

				if (spnego_state->downgraded) {
					/*
					 * A downgrade should be protected if
					 * supported
					 */
					break;
				}

				/*
				 * The caller may just asked for
				 * GENSEC_FEATURE_SESSION_KEY, this
				 * is only reflected in the want_features.
				 *
				 * As it will imply
				 * gensec_have_features(GENSEC_FEATURE_SIGN)
				 * to return true.
				 */
				if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
					break;
				}
				if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
					break;
				}
				/*
				 * Here we're sure our preferred mech was
				 * selected by the server and our caller doesn't
				 * need GENSEC_FEATURE_SIGN nor
				 * GENSEC_FEATURE_SEAL support.
				 *
				 * In this case we don't require
				 * a mechListMIC from the server.
				 *
				 * This works around bugs in the Azure
				 * and Apple spnego implementations.
				 *
				 * See
				 * https://bugzilla.samba.org/show_bug.cgi?id=11994
				 */
				spnego_state->may_skip_mic_check = true;
				break;

			case SPNEGO_REQUEST_MIC:
				if (spnego.negTokenTarg.mechListMIC.length > 0) {
					new_spnego = true;
				}
				break;
			default:
				break;
			}

			if (spnego_state->mic_requested) {
				if (have_sign) {
					new_spnego = true;
				}
			}

			if (have_sign && new_spnego) {
				spnego_state->needs_mic_check = true;
				spnego_state->needs_mic_sign = true;
			}
		}

		if (spnego.negTokenTarg.mechListMIC.length > 0) {
			nt_status = gensec_check_packet(spnego_state->sub_sec_security,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							spnego_state->mech_types.data,
							spnego_state->mech_types.length,
							&spnego.negTokenTarg.mechListMIC);
			if (!NT_STATUS_IS_OK(nt_status)) {
				DEBUG(2,("GENSEC SPNEGO: failed to verify mechListMIC: %s\n",
					nt_errstr(nt_status)));
				spnego_free_data(&spnego);
				return nt_status;
			}
			spnego_state->needs_mic_check = false;
			spnego_state->done_mic_check = true;
		}

		if (spnego_state->needs_mic_sign) {
			nt_status = gensec_sign_packet(spnego_state->sub_sec_security,
						       out_mem_ctx,
						       spnego_state->mech_types.data,
						       spnego_state->mech_types.length,
						       spnego_state->mech_types.data,
						       spnego_state->mech_types.length,
						       &mech_list_mic);
			if (!NT_STATUS_IS_OK(nt_status)) {
				DEBUG(2,("GENSEC SPNEGO: failed to sign mechListMIC: %s\n",
					nt_errstr(nt_status)));
				spnego_free_data(&spnego);
				return nt_status;
			}
			spnego_state->needs_mic_sign = false;
		}

		if (spnego_state->needs_mic_check) {
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		}

 client_response:
		spnego_free_data(&spnego);

		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)
			&& !NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("SPNEGO(%s) login failed: %s\n", 
				  spnego_state->sub_sec_security->ops->name, 
				  nt_errstr(nt_status)));
			return nt_status;
		}

		if (unwrapped_out.length || mech_list_mic.length) {
			/* compose reply */
			spnego_out.type = SPNEGO_NEG_TOKEN_TARG;
			spnego_out.negTokenTarg.negResult = SPNEGO_NONE_RESULT;
			spnego_out.negTokenTarg.supportedMech = NULL;
			spnego_out.negTokenTarg.responseToken = unwrapped_out;
			spnego_out.negTokenTarg.mechListMIC = mech_list_mic;

			if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
				DEBUG(1, ("Failed to write SPNEGO reply to NEG_TOKEN_TARG\n"));
				return NT_STATUS_INVALID_PARAMETER;
			}

			spnego_state->num_targs++;
			spnego_state->state_position = SPNEGO_CLIENT_TARG;
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		} else {

			/* all done - server has accepted, and we agree */
			*out = null_data_blob;

			if (spnego.negTokenTarg.negResult != SPNEGO_ACCEPT_COMPLETED) {
				/* unless of course it did not accept */
				DEBUG(1,("gensec_update ok but not accepted\n"));
				nt_status = NT_STATUS_INVALID_PARAMETER;
			}

			spnego_state->state_position = SPNEGO_DONE;
		}

		return nt_status;
	}
	case SPNEGO_DONE:
		/* We should not be called after we are 'done' */
		return NT_STATUS_INVALID_PARAMETER;
	}
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_spnego_update_in(struct gensec_security *gensec_security,
					const DATA_BLOB in, DATA_BLOB *full_in)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
	size_t expected;
	bool ok;

	*full_in = data_blob_null;

	if (spnego_state->in_needed == 0) {
		size_t size = 0;
		int ret;

		/*
		 * try to work out the size of the full
		 * input token, it might be fragmented
		 */
		ret = asn1_peek_full_tag(in,  ASN1_APPLICATION(0), &size);
		if ((ret != 0) && (ret != EAGAIN)) {
			ret = asn1_peek_full_tag(in, ASN1_CONTEXT(1), &size);
		}

		if ((ret == 0) || (ret == EAGAIN)) {
			spnego_state->in_needed = size;
		} else {
			/*
			 * If it is not an asn1 message
			 * just call the next layer.
			 */
			spnego_state->in_needed = in.length;
		}
	}

	if (spnego_state->in_needed > UINT16_MAX) {
		/*
		 * limit the incoming message to 0xFFFF
		 * to avoid DoS attacks.
		 */
		return NT_STATUS_INVALID_BUFFER_SIZE;
	}

	if ((spnego_state->in_needed > 0) && (in.length == 0)) {
		/*
		 * If we reach this, we know we got at least
		 * part of an asn1 message, getting 0 means
		 * the remote peer wants us to spin.
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	expected = spnego_state->in_needed - spnego_state->in_frag.length;
	if (in.length > expected) {
		/*
		 * we got more than expected
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in.length == spnego_state->in_needed) {
		/*
		 * if the in.length contains the full blob
		 * we are done.
		 *
		 * Note: this implies spnego_state->in_frag.length == 0,
		 *       but we do not need to check this explicitly
		 *       because we already know that we did not get
		 *       more than expected.
		 */
		*full_in = in;
		return NT_STATUS_OK;
	}

	ok = data_blob_append(spnego_state, &spnego_state->in_frag,
			      in.data, in.length);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	if (spnego_state->in_needed > spnego_state->in_frag.length) {
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	*full_in = spnego_state->in_frag;
	return NT_STATUS_OK;
}

static NTSTATUS gensec_spnego_update_out(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 DATA_BLOB *_out)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
	DATA_BLOB out = data_blob_null;
	bool ok;

	*_out = data_blob_null;

	if (spnego_state->out_frag.length == 0) {
		return spnego_state->out_status;
	}

	/*
	 * There is still more data to be delivered
	 * to the remote peer.
	 */

	if (spnego_state->out_frag.length <= spnego_state->out_max_length) {
		/*
		 * Fast path, we can deliver everything
		 */

		*_out = spnego_state->out_frag;
		talloc_steal(out_mem_ctx, _out->data);
		spnego_state->out_frag = data_blob_null;
		return spnego_state->out_status;
	}

	out = spnego_state->out_frag;

	/*
	 * copy the remaining bytes
	 */
	spnego_state->out_frag = data_blob_talloc(spnego_state,
					out.data + spnego_state->out_max_length,
					out.length - spnego_state->out_max_length);
	if (spnego_state->out_frag.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * truncate the buffer
	 */
	ok = data_blob_realloc(spnego_state, &out,
			       spnego_state->out_max_length);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	talloc_steal(out_mem_ctx, out.data);
	*_out = out;
	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS gensec_spnego_update_wrapper(struct gensec_security *gensec_security,
					     TALLOC_CTX *out_mem_ctx,
					     struct tevent_context *ev,
					     const DATA_BLOB in, DATA_BLOB *out)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
	DATA_BLOB full_in = data_blob_null;
	NTSTATUS status;

	*out = data_blob_null;

	if (spnego_state->out_frag.length > 0) {
		if (in.length > 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		return gensec_spnego_update_out(gensec_security,
						out_mem_ctx,
						out);
	}

	status = gensec_spnego_update_in(gensec_security,
					 in, &full_in);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gensec_spnego_update(gensec_security,
				      spnego_state, ev,
				      full_in,
				      &spnego_state->out_frag);
	data_blob_free(&spnego_state->in_frag);
	spnego_state->in_needed = 0;
	if (NT_STATUS_IS_OK(status)) {
		bool reset_full = true;

		gensec_security->child_security = spnego_state->sub_sec_security;

		reset_full = !spnego_state->done_mic_check;

		status = gensec_may_reset_crypto(spnego_state->sub_sec_security,
						 reset_full);
	}
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return status;
	}

	spnego_state->out_status = status;

	return gensec_spnego_update_out(gensec_security,
					out_mem_ctx,
					out);
}

static void gensec_spnego_want_feature(struct gensec_security *gensec_security,
				       uint32_t feature)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (!spnego_state || !spnego_state->sub_sec_security) {
		gensec_security->want_features |= feature;
		return;
	}

	gensec_want_feature(spnego_state->sub_sec_security,
			    feature);
}

static bool gensec_spnego_have_feature(struct gensec_security *gensec_security,
				       uint32_t feature) 
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
	if (!spnego_state->sub_sec_security) {
		return false;
	}

	return gensec_have_feature(spnego_state->sub_sec_security, 
				   feature);
}

static NTTIME gensec_spnego_expire_time(struct gensec_security *gensec_security)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;

	if (!spnego_state->sub_sec_security) {
		return GENSEC_EXPIRE_TIME_INFINITY;
	}

	return gensec_expire_time(spnego_state->sub_sec_security);
}

static const char *gensec_spnego_oids[] = { 
	GENSEC_OID_SPNEGO,
	NULL 
};

static const struct gensec_security_ops gensec_spnego_security_ops = {
	.name		  = "spnego",
	.sasl_name	  = "GSS-SPNEGO",
	.auth_type	  = DCERPC_AUTH_TYPE_SPNEGO,
	.oid              = gensec_spnego_oids,
	.client_start     = gensec_spnego_client_start,
	.server_start     = gensec_spnego_server_start,
	.update 	  = gensec_spnego_update_wrapper,
	.seal_packet	  = gensec_spnego_seal_packet,
	.sign_packet	  = gensec_spnego_sign_packet,
	.sig_size	  = gensec_spnego_sig_size,
	.max_wrapped_size = gensec_spnego_max_wrapped_size,
	.max_input_size	  = gensec_spnego_max_input_size,
	.check_packet	  = gensec_spnego_check_packet,
	.unseal_packet	  = gensec_spnego_unseal_packet,
	.wrap             = gensec_spnego_wrap,
	.unwrap           = gensec_spnego_unwrap,
	.session_key	  = gensec_spnego_session_key,
	.session_info     = gensec_spnego_session_info,
	.want_feature     = gensec_spnego_want_feature,
	.have_feature     = gensec_spnego_have_feature,
	.expire_time      = gensec_spnego_expire_time,
	.enabled          = true,
	.priority         = GENSEC_SPNEGO
};

_PUBLIC_ NTSTATUS gensec_spnego_init(void)
{
	NTSTATUS ret;
	ret = gensec_register(&gensec_spnego_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_spnego_security_ops.name));
		return ret;
	}

	return ret;
}
