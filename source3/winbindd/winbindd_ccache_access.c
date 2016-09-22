/*
   Unix SMB/CIFS implementation.

   Winbind daemon - cached credentials funcions

   Copyright (C) Robert O'Callahan 2006
   Copyright (C) Jeremy Allison 2006 (minor fixes to fit into Samba and
				      protect against integer wrap).
   Copyright (C) Andrew Bartlett 2011

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
#include "winbindd.h"
#include "auth/gensec/gensec.h"
#include "auth_generic.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static bool client_can_access_ccache_entry(uid_t client_uid,
					struct WINBINDD_MEMORY_CREDS *entry)
{
	if (client_uid == entry->uid || client_uid == 0) {
		DEBUG(10, ("Access granted to uid %u\n", (unsigned int)client_uid));
		return True;
	}

	DEBUG(1, ("Access denied to uid %u (expected %u)\n",
		(unsigned int)client_uid, (unsigned int)entry->uid));
	return False;
}

static NTSTATUS do_ntlm_auth_with_stored_pw(const char *username,
					    const char *domain,
					    const char *password,
					    const DATA_BLOB initial_msg,
					    const DATA_BLOB challenge_msg,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *auth_msg,
					    uint8_t session_key[16],
					    uint8_t *new_spnego)
{
	NTSTATUS status;
	struct auth_generic_state *auth_generic_state = NULL;
	DATA_BLOB reply, session_key_blob;

	status = auth_generic_client_prepare(mem_ctx, &auth_generic_state);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not start NTLMSSP client: %s\n",
			nt_errstr(status)));
		goto done;
	}

	status = auth_generic_set_username(auth_generic_state, username);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set username: %s\n",
			nt_errstr(status)));
		goto done;
	}

	status = auth_generic_set_domain(auth_generic_state, domain);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set domain: %s\n",
			nt_errstr(status)));
		goto done;
	}

	status = auth_generic_set_password(auth_generic_state, password);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set password: %s\n",
			nt_errstr(status)));
		goto done;
	}

	if (initial_msg.length == 0) {
		gensec_want_feature(auth_generic_state->gensec_security,
				    GENSEC_FEATURE_SESSION_KEY);
	}

	status = auth_generic_client_start_by_name(auth_generic_state,
						   "ntlmssp_resume_ccache");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not start NTLMSSP resume mech: %s\n",
			nt_errstr(status)));
		goto done;
	}

	/*
	 * We inject the inital NEGOTIATE message our caller used
	 * in order to get the state machine into the correct possition.
	 */
	reply = data_blob_null;
	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), initial_msg, &reply);
	data_blob_free(&reply);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(1, ("Failed to create initial message! [%s]\n",
			nt_errstr(status)));
		goto done;
	}

	/* Now we are ready to handle the server's actual response. */
	status = gensec_update(auth_generic_state->gensec_security,
			       mem_ctx, challenge_msg, &reply);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		DEBUG(1, ("We didn't get a response to the challenge! [%s]\n",
			nt_errstr(status)));
		data_blob_free(&reply);
		goto done;
	}

	status = gensec_session_key(auth_generic_state->gensec_security,
				    talloc_tos(), &session_key_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		DEBUG(1, ("We didn't get the session key we requested! [%s]\n",
			nt_errstr(status)));
		data_blob_free(&reply);
		goto done;
	}

	if (session_key_blob.length != 16) {
		DEBUG(1, ("invalid session key length %d\n",
			  (int)session_key_blob.length));
		data_blob_free(&reply);
		goto done;
	}
	memcpy(session_key, session_key_blob.data, 16);
	data_blob_free(&session_key_blob);
	*auth_msg = reply;
	*new_spnego = gensec_have_feature(auth_generic_state->gensec_security,
					  GENSEC_FEATURE_NEW_SPNEGO);
	status = NT_STATUS_OK;

done:
	TALLOC_FREE(auth_generic_state);
	return status;
}

static bool check_client_uid(struct winbindd_cli_state *state, uid_t uid)
{
	int ret;
	uid_t ret_uid;
	gid_t ret_gid;

	ret_uid = (uid_t)-1;

	ret = getpeereid(state->sock, &ret_uid, &ret_gid);
	if (ret != 0) {
		DEBUG(1, ("check_client_uid: Could not get socket peer uid: %s; "
			"denying access\n", strerror(errno)));
		return False;
	}

	if (uid != ret_uid && ret_uid != sec_initial_uid()) {
		DEBUG(1, ("check_client_uid: Client lied about its uid: said %u, "
			"actually was %u; denying access\n",
			(unsigned int)uid, (unsigned int)ret_uid));
		return False;
	}

	return True;
}

void winbindd_ccache_ntlm_auth(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	fstring name_domain, name_user;
	NTSTATUS result = NT_STATUS_NOT_SUPPORTED;
	struct WINBINDD_MEMORY_CREDS *entry;
	DATA_BLOB initial, challenge, auth;
	uint32_t initial_blob_len, challenge_blob_len, extra_len;

	/* Ensure null termination */
	state->request->data.ccache_ntlm_auth.user[
			sizeof(state->request->data.ccache_ntlm_auth.user)-1]='\0';

	DEBUG(3, ("[%5lu]: perform NTLM auth on behalf of user %s\n", (unsigned long)state->pid,
		state->request->data.ccache_ntlm_auth.user));

	/* Parse domain and username */

	if (!canonicalize_username(state->request->data.ccache_ntlm_auth.user,
				name_domain, name_user)) {
		DEBUG(5,("winbindd_ccache_ntlm_auth: cannot parse domain and user from name [%s]\n",
			state->request->data.ccache_ntlm_auth.user));
		request_error(state);
		return;
	}

	domain = find_auth_domain(state->request->flags, name_domain);

	if (domain == NULL) {
		DEBUG(5,("winbindd_ccache_ntlm_auth: can't get domain [%s]\n",
			name_domain));
		request_error(state);
		return;
	}

	if (!check_client_uid(state, state->request->data.ccache_ntlm_auth.uid)) {
		request_error(state);
		return;
	}

	/* validate blob lengths */
	initial_blob_len = state->request->data.ccache_ntlm_auth.initial_blob_len;
	challenge_blob_len = state->request->data.ccache_ntlm_auth.challenge_blob_len;
	extra_len = state->request->extra_len;

	if (initial_blob_len > extra_len || challenge_blob_len > extra_len ||
		initial_blob_len + challenge_blob_len > extra_len ||
		initial_blob_len + challenge_blob_len < initial_blob_len ||
		initial_blob_len + challenge_blob_len < challenge_blob_len) {

		DEBUG(10,("winbindd_dual_ccache_ntlm_auth: blob lengths overrun "
			"or wrap. Buffer [%d+%d > %d]\n",
			initial_blob_len,
			challenge_blob_len,
			extra_len));
		goto process_result;
	}

	/* Parse domain and username */
	if (!parse_domain_user(state->request->data.ccache_ntlm_auth.user, name_domain, name_user)) {
		DEBUG(10,("winbindd_dual_ccache_ntlm_auth: cannot parse "
			"domain and user from name [%s]\n",
			state->request->data.ccache_ntlm_auth.user));
		goto process_result;
	}

	entry = find_memory_creds_by_name(state->request->data.ccache_ntlm_auth.user);
	if (entry == NULL || entry->nt_hash == NULL || entry->lm_hash == NULL) {
		DEBUG(10,("winbindd_dual_ccache_ntlm_auth: could not find "
			"credentials for user %s\n", 
			state->request->data.ccache_ntlm_auth.user));
		goto process_result;
	}

	DEBUG(10,("winbindd_dual_ccache_ntlm_auth: found ccache [%s]\n", entry->username));

	if (!client_can_access_ccache_entry(state->request->data.ccache_ntlm_auth.uid, entry)) {
		goto process_result;
	}

	if (initial_blob_len == 0 && challenge_blob_len == 0) {
		/* this is just a probe to see if credentials are available. */
		result = NT_STATUS_OK;
		state->response->data.ccache_ntlm_auth.auth_blob_len = 0;
		goto process_result;
	}

	initial = data_blob_const(state->request->extra_data.data,
				  initial_blob_len);
	challenge = data_blob_const(
		state->request->extra_data.data + initial_blob_len,
		state->request->data.ccache_ntlm_auth.challenge_blob_len);

	result = do_ntlm_auth_with_stored_pw(
		name_user, name_domain, entry->pass,
		initial, challenge, talloc_tos(), &auth,
		state->response->data.ccache_ntlm_auth.session_key,
		&state->response->data.ccache_ntlm_auth.new_spnego);

	if (!NT_STATUS_IS_OK(result)) {
		goto process_result;
	}

	state->response->extra_data.data = talloc_memdup(
		state->mem_ctx, auth.data, auth.length);
	if (!state->response->extra_data.data) {
		result = NT_STATUS_NO_MEMORY;
		goto process_result;
	}
	state->response->length += auth.length;
	state->response->data.ccache_ntlm_auth.auth_blob_len = auth.length;

	data_blob_free(&auth);

  process_result:
	if (!NT_STATUS_IS_OK(result)) {
		request_error(state);
		return;
	}
	request_ok(state);
}

void winbindd_ccache_save(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	fstring name_domain, name_user;
	NTSTATUS status;

	/* Ensure null termination */
	state->request->data.ccache_save.user[
		sizeof(state->request->data.ccache_save.user)-1]='\0';
	state->request->data.ccache_save.pass[
		sizeof(state->request->data.ccache_save.pass)-1]='\0';

	DEBUG(3, ("[%5lu]: save password of user %s\n",
		  (unsigned long)state->pid,
		  state->request->data.ccache_save.user));

	/* Parse domain and username */

	if (!canonicalize_username(state->request->data.ccache_save.user,
				   name_domain, name_user)) {
		DEBUG(5,("winbindd_ccache_save: cannot parse domain and user "
			 "from name [%s]\n",
			 state->request->data.ccache_save.user));
		request_error(state);
		return;
	}

	/*
	 * The domain is checked here only for compatibility
	 * reasons. We used to do the winbindd memory ccache for
	 * ntlm_auth in the domain child. With that code, we had to
	 * make sure that we do have a domain around to send this
	 * to. Now we do the memory cache in the parent winbindd,
	 * where it would not matter if we have a domain or not.
	 */

	domain = find_auth_domain(state->request->flags, name_domain);
	if (domain == NULL) {
		DEBUG(5, ("winbindd_ccache_save: can't get domain [%s]\n",
			  name_domain));
		request_error(state);
		return;
	}

	if (!check_client_uid(state, state->request->data.ccache_save.uid)) {
		request_error(state);
		return;
	}

	status = winbindd_add_memory_creds(
		state->request->data.ccache_save.user,
		state->request->data.ccache_save.uid,
		state->request->data.ccache_save.pass);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("winbindd_add_memory_creds failed %s\n",
			  nt_errstr(status)));
		request_error(state);
		return;
	}
	request_ok(state);
}
