/*
   Unix SMB/CIFS implementation.

   test suite for netlogon PAC operations

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2012

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
#include "auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "auth/gensec/gensec.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "lib/cmdline/popt_common.h"
#include "torture/rpc/torture_rpc.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "param/param.h"

#define TEST_MACHINE_NAME_BDC "torturepacbdc"
#define TEST_MACHINE_NAME_WKSTA "torturepacwksta"
#define TEST_MACHINE_NAME_WKSTA_DES "torturepacwkdes"
#define TEST_MACHINE_NAME_S2U4SELF_BDC "tests2u4selfbdc"
#define TEST_MACHINE_NAME_S2U4SELF_WKSTA "tests2u4selfwk"

struct pac_data {
	DATA_BLOB pac_blob;
	struct PAC_SIGNATURE_DATA *pac_srv_sig;
	struct PAC_SIGNATURE_DATA *pac_kdc_sig;
};

/* A helper function which avoids touching the local databases to
 * generate the session info, as we just want to verify the PAC
 * details, not the full local token */
static NTSTATUS test_generate_session_info_pac(struct auth4_context *auth_ctx,
					       TALLOC_CTX *mem_ctx,
					       struct smb_krb5_context *smb_krb5_context,
					       DATA_BLOB *pac_blob,
					       const char *principal_name,
					       const struct tsocket_address *remote_address,
					       uint32_t session_info_flags,
					       struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc;
	TALLOC_CTX *tmp_ctx;
	struct pac_data *pac_data;

	tmp_ctx = talloc_named(mem_ctx, 0, "gensec_gssapi_session_info context");
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	auth_ctx->private_data = pac_data = talloc_zero(auth_ctx, struct pac_data);

	pac_data->pac_blob = data_blob_dup_talloc(pac_data, *pac_blob);
	if (pac_data->pac_blob.length != pac_blob->length) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	pac_data->pac_srv_sig = talloc(tmp_ctx, struct PAC_SIGNATURE_DATA);
	if (!pac_data->pac_srv_sig) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	pac_data->pac_kdc_sig = talloc(tmp_ctx, struct PAC_SIGNATURE_DATA);
	if (!pac_data->pac_kdc_sig) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = kerberos_pac_blob_to_user_info_dc(tmp_ctx,
						      *pac_blob,
						      smb_krb5_context->krb5_context,
						      &user_info_dc,
						      pac_data->pac_srv_sig,
						      pac_data->pac_kdc_sig);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_steal(pac_data, pac_data->pac_srv_sig);
	talloc_steal(pac_data, pac_data->pac_kdc_sig);

	if (user_info_dc->info->authenticated) {
		session_info_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;
	nt_status = auth_generate_session_info(mem_ctx,
					       NULL,
					       NULL,
					       user_info_dc, session_info_flags,
					       session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_free(tmp_ctx);
	return nt_status;
}

/* Check to see if we can pass the PAC across to the NETLOGON server for validation */

/* Also happens to be a really good one-step verfication of our Kerberos stack */

static bool test_PACVerify(struct torture_context *tctx,
			   struct dcerpc_pipe *p1,
			   struct cli_credentials *credentials,
			   enum netr_SchannelType secure_channel_type,
			   const char *test_machine_name,
			   uint32_t negotiate_flags)
{
	NTSTATUS status;
	bool pkinit_in_use = torture_setting_bool(tctx, "pkinit_in_use", false);
	bool expect_pac_upn_dns_info = torture_setting_bool(tctx, "expect_pac_upn_dns_info", true);
	size_t num_pac_buffers;

	struct netr_LogonSamLogon r;

	union netr_LogonLevel logon;
	union netr_Validation validation;
	uint8_t authoritative;
	struct netr_Authenticator return_authenticator;

	struct netr_GenericInfo generic;
	struct netr_Authenticator auth, auth2;

	struct netlogon_creds_CredentialState *creds;
	struct gensec_security *gensec_client_context;
	struct gensec_security *gensec_server_context;
	struct cli_credentials *client_creds;
	struct cli_credentials *server_creds;

	DATA_BLOB client_to_server, server_to_client, pac_wrapped, payload;
	struct PAC_Validate pac_wrapped_struct;
	struct PAC_DATA pac_data_struct;

	enum ndr_err_code ndr_err;

	struct auth4_context *auth_context;
	struct auth_session_info *session_info;
	struct pac_data *pac_data;
	const struct PAC_BUFFER *pac_buf = NULL;

	struct dcerpc_pipe *p = NULL;
	struct dcerpc_binding_handle *b = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	torture_assert(tctx, tmp_ctx != NULL, "talloc_new() failed");

	torture_comment(tctx,
		"Testing PAC Verify (secure_channel_type: %d, machine: %s, negotiate_flags: 0x%08x\n",
		secure_channel_type, test_machine_name, negotiate_flags);

	/*
	 * Copy the credentials in order to use a different MEMORY krb5 ccache
	 * for each client/server setup. The MEMORY cache identifier is a
	 * pointer to the creds container. If we copy it the pointer changes and
	 * we will get a new clean memory cache.
	 */
	client_creds = cli_credentials_shallow_copy(tmp_ctx,
						    cmdline_credentials);
	torture_assert(tctx, client_creds, "Failed to copy of credentials");
	if (!pkinit_in_use) {
		/* Invalidate the gss creds container to allocate a new MEMORY ccache */
		cli_credentials_invalidate_ccache(client_creds, CRED_SPECIFIED);
	}

	server_creds = cli_credentials_shallow_copy(tmp_ctx,
						    credentials);
	torture_assert(tctx, server_creds, "Failed to copy of credentials");

	if (!test_SetupCredentials2(p1, tctx, negotiate_flags,
				    server_creds, secure_channel_type,
				    &creds)) {
		return false;
	}
	if (!test_SetupCredentialsPipe(p1, tctx, server_creds, creds,
				       DCERPC_SIGN | DCERPC_SEAL, &p)) {
		return false;
	}
	b = p->binding_handle;

	auth_context = talloc_zero(tmp_ctx, struct auth4_context);
	torture_assert(tctx, auth_context != NULL, "talloc_new() failed");

	auth_context->generate_session_info_pac = test_generate_session_info_pac;

	status = gensec_client_start(tctx, &gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "gensec_client_start (client) failed");

	status = gensec_set_target_hostname(gensec_client_context, test_machine_name);

	status = gensec_set_credentials(gensec_client_context, client_creds);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	status = gensec_server_start(tctx,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				     auth_context, &gensec_server_context);
	torture_assert_ntstatus_ok(tctx, status, "gensec_server_start (server) failed");

	status = gensec_set_credentials(gensec_server_context, server_creds);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (server) failed");

	status = gensec_start_mech_by_sasl_name(gensec_server_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (server) failed");

	server_to_client = data_blob(NULL, 0);

	do {
		/* Do a client-server update dance */
		status = gensec_update(gensec_client_context, tmp_ctx, server_to_client, &client_to_server);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
		}

		status = gensec_update(gensec_server_context, tmp_ctx, client_to_server, &server_to_client);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (server) failed");
		}

		if (NT_STATUS_IS_OK(status)) {
			break;
		}
	} while (1);

	/* Extract the PAC using Samba's code */

	status = gensec_session_info(gensec_server_context, gensec_server_context, &session_info);
	torture_assert_ntstatus_ok(tctx, status, "gensec_session_info failed");

	pac_data = talloc_get_type(auth_context->private_data, struct pac_data);

	torture_assert(tctx, pac_data != NULL, "gensec_update failed to fill in pac_data in auth_context");
	torture_assert(tctx, pac_data->pac_srv_sig != NULL, "pac_srv_sig not present");
	torture_assert(tctx, pac_data->pac_kdc_sig != NULL, "pac_kdc_sig not present");

	ndr_err = ndr_pull_struct_blob(&pac_data->pac_blob, tmp_ctx, &pac_data_struct,
				       (ndr_pull_flags_fn_t)ndr_pull_PAC_DATA);
	torture_assert(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), "ndr_pull_struct_blob of PAC_DATA structure failed");

	num_pac_buffers = 4;
	if (expect_pac_upn_dns_info) {
		num_pac_buffers += 1;
	}
	if (pkinit_in_use) {
		num_pac_buffers += 1;
	}

	torture_assert_int_equal(tctx, pac_data_struct.version, 0, "version");
	torture_assert_int_equal(tctx, pac_data_struct.num_buffers, num_pac_buffers, "num_buffers");

	pac_buf = pac_data_struct.buffers;
	torture_assert_int_equal(tctx, pac_buf->type,
				 PAC_TYPE_LOGON_INFO, "PAC_TYPE_LOGON_INFO");
	torture_assert(tctx, pac_buf->info != NULL,
		       "PAC_TYPE_LOGON_INFO info");
	pac_buf++;
	if (pkinit_in_use) {
		torture_assert_int_equal(tctx, pac_buf->type,
					 PAC_TYPE_CREDENTIAL_INFO,
					 "PAC_TYPE_CREDENTIAL_INFO");
		torture_assert(tctx, pac_buf->info != NULL,
			       "PAC_TYPE_CREDENTIAL_INFO info");
		pac_buf++;
	}
	torture_assert_int_equal(tctx, pac_buf->type,
				 PAC_TYPE_LOGON_NAME, "PAC_TYPE_LOGON_NAME");
	torture_assert(tctx, pac_buf->info != NULL,
		       "PAC_TYPE_LOGON_NAME info");
	pac_buf++;
	if (expect_pac_upn_dns_info) {
		torture_assert_int_equal(tctx, pac_buf->type,
					 PAC_TYPE_UPN_DNS_INFO, "PAC_TYPE_UPN_DNS_INFO");
		torture_assert(tctx, pac_buf->info != NULL,
			       "PAC_TYPE_UPN_DNS_INFO info");
		pac_buf++;
	}
	torture_assert_int_equal(tctx, pac_buf->type,
				 PAC_TYPE_SRV_CHECKSUM, "PAC_TYPE_SRV_CHECKSUM");
	torture_assert(tctx, pac_buf->info != NULL,
		       "PAC_TYPE_SRV_CHECKSUM info");
	pac_buf++;
	torture_assert_int_equal(tctx, pac_buf->type,
				 PAC_TYPE_KDC_CHECKSUM, "PAC_TYPE_KDC_CHECKSUM");
	torture_assert(tctx, pac_buf->info != NULL,
		       "PAC_TYPE_KDC_CHECKSUM info");
	pac_buf++;

	pac_wrapped_struct.ChecksumLength = pac_data->pac_srv_sig->signature.length;
	pac_wrapped_struct.SignatureType = pac_data->pac_kdc_sig->type;
	pac_wrapped_struct.SignatureLength = pac_data->pac_kdc_sig->signature.length;
	pac_wrapped_struct.ChecksumAndSignature = payload
		= data_blob_talloc(tmp_ctx, NULL,
				   pac_wrapped_struct.ChecksumLength
				   + pac_wrapped_struct.SignatureLength);
	memcpy(&payload.data[0],
	       pac_data->pac_srv_sig->signature.data,
	       pac_wrapped_struct.ChecksumLength);
	memcpy(&payload.data[pac_wrapped_struct.ChecksumLength],
	       pac_data->pac_kdc_sig->signature.data,
	       pac_wrapped_struct.SignatureLength);

	ndr_err = ndr_push_struct_blob(&pac_wrapped, tmp_ctx, &pac_wrapped_struct,
				       (ndr_push_flags_fn_t)ndr_push_PAC_Validate);
	torture_assert(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), "ndr_push_struct_blob of PACValidate structure failed");

	torture_assert(tctx, (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR), "not willing to even try a PACValidate without RC4 encryption");
	if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		netlogon_creds_aes_encrypt(creds, pac_wrapped.data, pac_wrapped.length);
	} else {
		netlogon_creds_arcfour_crypt(creds, pac_wrapped.data, pac_wrapped.length);
	}

	generic.length = pac_wrapped.length;
	generic.data = pac_wrapped.data;

	/* Validate it over the netlogon pipe */

	generic.identity_info.parameter_control = 0;
	generic.identity_info.logon_id_high = 0;
	generic.identity_info.logon_id_low = 0;
	generic.identity_info.domain_name.string = session_info->info->domain_name;
	generic.identity_info.account_name.string = session_info->info->account_name;
	generic.identity_info.workstation.string = test_machine_name;

	generic.package_name.string = "Kerberos";

	logon.generic = &generic;

	ZERO_STRUCT(auth2);
	netlogon_creds_client_authenticator(creds, &auth);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon = &logon;
	r.in.logon_level = NetlogonGenericInformation;
	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(server_creds);
	r.in.validation_level = NetlogonValidationGenericInfo2;
	r.out.validation = &validation;
	r.out.authoritative = &authoritative;
	r.out.return_authenticator = &return_authenticator;

	torture_assert_ntstatus_ok(tctx, dcerpc_netr_LogonSamLogon_r(b, tctx, &r),
		"LogonSamLogon failed");

	torture_assert_ntstatus_ok(tctx, r.out.result, "LogonSamLogon failed");

	/* This will break the signature nicely (even in the crypto wrapping), check we get a logon failure */
	generic.data[generic.length-1]++;

	logon.generic = &generic;

	ZERO_STRUCT(auth2);
	netlogon_creds_client_authenticator(creds, &auth);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = NetlogonGenericInformation;
	r.in.logon = &logon;
	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(server_creds);
	r.in.validation_level = NetlogonValidationGenericInfo2;

	torture_assert_ntstatus_ok(tctx, dcerpc_netr_LogonSamLogon_r(b, tctx, &r),
		"LogonSamLogon failed");

	torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_LOGON_FAILURE, "LogonSamLogon failed");

	torture_assert(tctx, netlogon_creds_client_check(creds, &r.out.return_authenticator->cred),
		       "Credential chaining failed");

	/* This will break the parsing nicely (even in the crypto wrapping), check we get INVALID_PARAMETER */
	generic.length--;

	logon.generic = &generic;

	ZERO_STRUCT(auth2);
	netlogon_creds_client_authenticator(creds, &auth);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = NetlogonGenericInformation;
	r.in.logon = &logon;
	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(server_creds);
	r.in.validation_level = NetlogonValidationGenericInfo2;

	torture_assert_ntstatus_ok(tctx, dcerpc_netr_LogonSamLogon_r(b, tctx, &r),
		"LogonSamLogon failed");

	torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_INVALID_PARAMETER, "LogonSamLogon failed");

	torture_assert(tctx, netlogon_creds_client_check(creds,
							 &r.out.return_authenticator->cred),
		       "Credential chaining failed");

	pac_wrapped_struct.ChecksumLength = pac_data->pac_srv_sig->signature.length;
	pac_wrapped_struct.SignatureType = pac_data->pac_kdc_sig->type;

	/* Break the SignatureType */
	pac_wrapped_struct.SignatureType++;

	pac_wrapped_struct.SignatureLength = pac_data->pac_kdc_sig->signature.length;
	pac_wrapped_struct.ChecksumAndSignature = payload
		= data_blob_talloc(tmp_ctx, NULL,
				   pac_wrapped_struct.ChecksumLength
				   + pac_wrapped_struct.SignatureLength);
	memcpy(&payload.data[0],
	       pac_data->pac_srv_sig->signature.data,
	       pac_wrapped_struct.ChecksumLength);
	memcpy(&payload.data[pac_wrapped_struct.ChecksumLength],
	       pac_data->pac_kdc_sig->signature.data,
	       pac_wrapped_struct.SignatureLength);

	ndr_err = ndr_push_struct_blob(&pac_wrapped, tmp_ctx, &pac_wrapped_struct,
				       (ndr_push_flags_fn_t)ndr_push_PAC_Validate);
	torture_assert(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), "ndr_push_struct_blob of PACValidate structure failed");

	torture_assert(tctx, (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR), "not willing to even try a PACValidate without RC4 encryption");
	if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		netlogon_creds_aes_encrypt(creds, pac_wrapped.data, pac_wrapped.length);
	} else {
		netlogon_creds_arcfour_crypt(creds, pac_wrapped.data, pac_wrapped.length);
	}

	generic.length = pac_wrapped.length;
	generic.data = pac_wrapped.data;

	logon.generic = &generic;

	ZERO_STRUCT(auth2);
	netlogon_creds_client_authenticator(creds, &auth);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = NetlogonGenericInformation;
	r.in.logon = &logon;
	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(server_creds);
	r.in.validation_level = NetlogonValidationGenericInfo2;

	torture_assert_ntstatus_ok(tctx, dcerpc_netr_LogonSamLogon_r(b, tctx, &r),
		"LogonSamLogon failed");

	torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_LOGON_FAILURE, "LogonSamLogon failed");

	torture_assert(tctx, netlogon_creds_client_check(creds, &r.out.return_authenticator->cred),
		       "Credential chaining failed");

	pac_wrapped_struct.ChecksumLength = pac_data->pac_srv_sig->signature.length;
	pac_wrapped_struct.SignatureType = pac_data->pac_kdc_sig->type;
	pac_wrapped_struct.SignatureLength = pac_data->pac_kdc_sig->signature.length;

	pac_wrapped_struct.ChecksumAndSignature = payload
		= data_blob_talloc(tmp_ctx, NULL,
				   pac_wrapped_struct.ChecksumLength
				   + pac_wrapped_struct.SignatureLength);
	memcpy(&payload.data[0],
	       pac_data->pac_srv_sig->signature.data,
	       pac_wrapped_struct.ChecksumLength);
	memcpy(&payload.data[pac_wrapped_struct.ChecksumLength],
	       pac_data->pac_kdc_sig->signature.data,
	       pac_wrapped_struct.SignatureLength);

	/* Break the signature length */
	pac_wrapped_struct.SignatureLength++;

	ndr_err = ndr_push_struct_blob(&pac_wrapped, tmp_ctx, &pac_wrapped_struct,
				       (ndr_push_flags_fn_t)ndr_push_PAC_Validate);
	torture_assert(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), "ndr_push_struct_blob of PACValidate structure failed");

	torture_assert(tctx, (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR), "not willing to even try a PACValidate without RC4 encryption");
	if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		netlogon_creds_aes_encrypt(creds, pac_wrapped.data, pac_wrapped.length);
	} else {
		netlogon_creds_arcfour_crypt(creds, pac_wrapped.data, pac_wrapped.length);
	}

	generic.length = pac_wrapped.length;
	generic.data = pac_wrapped.data;

	logon.generic = &generic;

	ZERO_STRUCT(auth2);
	netlogon_creds_client_authenticator(creds, &auth);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = NetlogonGenericInformation;
	r.in.logon = &logon;
	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(server_creds);
	r.in.validation_level = NetlogonValidationGenericInfo2;

	torture_assert_ntstatus_ok(tctx, dcerpc_netr_LogonSamLogon_r(b, tctx, &r),
		"LogonSamLogon failed");

	torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_INVALID_PARAMETER, "LogonSamLogon failed");

	torture_assert(tctx, netlogon_creds_client_check(creds, &r.out.return_authenticator->cred),
		       "Credential chaining failed");

	talloc_free(tmp_ctx);

	return true;
}

static bool test_PACVerify_bdc_arcfour(struct torture_context *tctx,
				       struct dcerpc_pipe *p,
				       struct cli_credentials *credentials)
{
	return test_PACVerify(tctx, p, credentials, SEC_CHAN_BDC,
			      TEST_MACHINE_NAME_BDC,
			      NETLOGON_NEG_AUTH2_ADS_FLAGS);
}

static bool test_PACVerify_bdc_aes(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   struct cli_credentials *credentials)
{
	return test_PACVerify(tctx, p, credentials, SEC_CHAN_BDC,
			      TEST_MACHINE_NAME_BDC,
			      NETLOGON_NEG_AUTH2_ADS_FLAGS | NETLOGON_NEG_SUPPORTS_AES);
}

static bool test_PACVerify_workstation_arcfour(struct torture_context *tctx,
					       struct dcerpc_pipe *p,
					       struct cli_credentials *credentials)
{
	return test_PACVerify(tctx, p, credentials, SEC_CHAN_WKSTA,
			      TEST_MACHINE_NAME_WKSTA,
			      NETLOGON_NEG_AUTH2_ADS_FLAGS);
}

static bool test_PACVerify_workstation_aes(struct torture_context *tctx,
					   struct dcerpc_pipe *p,
					   struct cli_credentials *credentials)
{
	return test_PACVerify(tctx, p, credentials, SEC_CHAN_WKSTA,
			      TEST_MACHINE_NAME_WKSTA,
			      NETLOGON_NEG_AUTH2_ADS_FLAGS | NETLOGON_NEG_SUPPORTS_AES);
}

static bool test_PACVerify_workstation_des(struct torture_context *tctx,
					   struct dcerpc_pipe *p, struct cli_credentials *credentials, struct test_join *join_ctx)
{
	struct samr_SetUserInfo r;
	union samr_UserInfo user_info;
	struct dcerpc_pipe *samr_pipe = torture_join_samr_pipe(join_ctx);
	struct smb_krb5_context *smb_krb5_context;
	krb5_error_code ret;

	ret = cli_credentials_get_krb5_context(cmdline_credentials, tctx->lp_ctx, &smb_krb5_context);
	torture_assert_int_equal(tctx, ret, 0, "cli_credentials_get_krb5_context() failed");

	if (smb_krb5_get_allowed_weak_crypto(smb_krb5_context->krb5_context) == FALSE) {
		torture_skip(tctx, "Cannot test DES without [libdefaults] allow_weak_crypto = yes");
	}

	/* Mark this workstation with DES-only */
	user_info.info16.acct_flags = ACB_USE_DES_KEY_ONLY | ACB_WSTRUST;
	r.in.user_handle = torture_join_samr_user_policy(join_ctx);
	r.in.level = 16;
	r.in.info = &user_info;

	torture_assert_ntstatus_ok(tctx, dcerpc_samr_SetUserInfo_r(samr_pipe->binding_handle, tctx, &r),
		"failed to set DES info account flags");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"failed to set DES into account flags");

	return test_PACVerify(tctx, p, credentials, SEC_CHAN_WKSTA,
			      TEST_MACHINE_NAME_WKSTA_DES,
			      NETLOGON_NEG_AUTH2_ADS_FLAGS);
}


/* Check various ways to get the PAC, in particular check the group membership and other details between the PAC from a normal kinit, S2U4Self and a SamLogon */
static bool test_S2U4Self(struct torture_context *tctx,
			  struct dcerpc_pipe *p1,
			  struct cli_credentials *credentials,
			  enum netr_SchannelType secure_channel_type,
			  const char *test_machine_name,
			  uint32_t negotiate_flags)
{
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;
	struct dcerpc_binding_handle *b = NULL;

	struct netr_LogonSamLogon r;

	union netr_LogonLevel logon;
	union netr_Validation validation;
	uint8_t authoritative;

	struct netr_Authenticator auth, auth2;

	DATA_BLOB client_to_server, server_to_client;

	struct netlogon_creds_CredentialState *creds;
	struct gensec_security *gensec_client_context;
	struct gensec_security *gensec_server_context;
	struct cli_credentials *client_creds;
	struct cli_credentials *server_creds;

	struct auth4_context *auth_context;
	struct auth_session_info *kinit_session_info;
	struct auth_session_info *s2u4self_session_info;
	struct auth_user_info_dc *netlogon_user_info_dc;

	struct netr_NetworkInfo ninfo;
	DATA_BLOB names_blob, chal, lm_resp, nt_resp;
	size_t i;
	int flags = CLI_CRED_NTLMv2_AUTH;

	struct dom_sid *builtin_domain;

	TALLOC_CTX *tmp_ctx = talloc_new(tctx);

	torture_assert(tctx, tmp_ctx != NULL, "talloc_new() failed");

	torture_comment(tctx,
		"Testing S4U2SELF (secure_channel_type: %d, machine: %s, negotiate_flags: 0x%08x\n",
		secure_channel_type, test_machine_name, negotiate_flags);

	/*
	 * Copy the credentials in order to use a different MEMORY krb5 ccache
	 * for each client/server setup. The MEMORY cache identifier is a
	 * pointer to the creds container. If we copy it the pointer changes and
	 * we will get a new clean memory cache.
	 */
	client_creds = cli_credentials_shallow_copy(tmp_ctx,
						    cmdline_credentials);
	torture_assert(tctx, client_creds, "Failed to copy of credentials");

	server_creds = cli_credentials_shallow_copy(tmp_ctx,
						    credentials);
	torture_assert(tctx, server_creds, "Failed to copy of credentials");

	if (!test_SetupCredentials2(p1, tctx, negotiate_flags,
				    server_creds, secure_channel_type,
				    &creds)) {
		return false;
	}
	if (!test_SetupCredentialsPipe(p1, tctx, server_creds, creds,
				       DCERPC_SIGN | DCERPC_SEAL, &p)) {
		return false;
	}
	b = p->binding_handle;

	auth_context = talloc_zero(tmp_ctx, struct auth4_context);
	torture_assert(tctx, auth_context != NULL, "talloc_new() failed");

	auth_context->generate_session_info_pac = test_generate_session_info_pac;

	/* First, do a normal Kerberos connection */

	status = gensec_client_start(tctx, &gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "gensec_client_start (client) failed");

	status = gensec_set_target_hostname(gensec_client_context, test_machine_name);

	status = gensec_set_credentials(gensec_client_context, client_creds);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	status = gensec_server_start(tctx,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				     auth_context, &gensec_server_context);
	torture_assert_ntstatus_ok(tctx, status, "gensec_server_start (server) failed");

	status = gensec_set_credentials(gensec_server_context, server_creds);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (server) failed");

	status = gensec_start_mech_by_sasl_name(gensec_server_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (server) failed");

	server_to_client = data_blob(NULL, 0);

	do {
		/* Do a client-server update dance */
		status = gensec_update(gensec_client_context, tmp_ctx, server_to_client, &client_to_server);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
		}

		status = gensec_update(gensec_server_context, tmp_ctx, client_to_server, &server_to_client);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (server) failed");
		}

		if (NT_STATUS_IS_OK(status)) {
			break;
		}
	} while (1);

	/* Extract the PAC using Samba's code */

	status = gensec_session_info(gensec_server_context, gensec_server_context, &kinit_session_info);
	torture_assert_ntstatus_ok(tctx, status, "gensec_session_info failed");


	/* Now do the dance with S2U4Self */

	/* Wipe out any existing ccache */
	cli_credentials_invalidate_ccache(client_creds, CRED_SPECIFIED);
	cli_credentials_invalidate_ccache(server_creds, CRED_SPECIFIED);
	cli_credentials_set_impersonate_principal(server_creds,
			cli_credentials_get_principal(client_creds, tmp_ctx),
			talloc_asprintf(tmp_ctx, "host/%s", test_machine_name));

	status = gensec_client_start(tctx, &gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "gensec_client_start (client) failed");

	status = gensec_set_target_hostname(gensec_client_context, test_machine_name);

	/* We now set the same credentials on both client and server contexts */
	status = gensec_set_credentials(gensec_client_context, server_creds);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	status = gensec_server_start(tctx,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				     auth_context, &gensec_server_context);
	torture_assert_ntstatus_ok(tctx, status, "gensec_server_start (server) failed");

	status = gensec_set_credentials(gensec_server_context, server_creds);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (server) failed");

	status = gensec_start_mech_by_sasl_name(gensec_server_context, "GSSAPI");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (server) failed");

	server_to_client = data_blob(NULL, 0);

	do {
		/* Do a client-server update dance */
		status = gensec_update(gensec_client_context, tmp_ctx, server_to_client, &client_to_server);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
		}

		status = gensec_update(gensec_server_context, tmp_ctx, client_to_server, &server_to_client);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
			torture_assert_ntstatus_ok(tctx, status, "gensec_update (server) failed");
		}

		if (NT_STATUS_IS_OK(status)) {
			break;
		}
	} while (1);

	/* Don't pollute the remaining tests with the changed credentials */
	cli_credentials_invalidate_ccache(server_creds, CRED_SPECIFIED);
	cli_credentials_set_target_service(server_creds, NULL);
	cli_credentials_set_impersonate_principal(server_creds, NULL, NULL);

	/* Extract the PAC using Samba's code */

	status = gensec_session_info(gensec_server_context, gensec_server_context, &s2u4self_session_info);
	torture_assert_ntstatus_ok(tctx, status, "gensec_session_info failed");

	cli_credentials_get_ntlm_username_domain(client_creds, tctx,
						 &ninfo.identity_info.account_name.string,
						 &ninfo.identity_info.domain_name.string);

	/* Now try with SamLogon */
	generate_random_buffer(ninfo.challenge,
			       sizeof(ninfo.challenge));
	chal = data_blob_const(ninfo.challenge,
			       sizeof(ninfo.challenge));

	names_blob = NTLMv2_generate_names_blob(tctx, cli_credentials_get_workstation(server_creds),
						cli_credentials_get_domain(server_creds));

	status = cli_credentials_get_ntlm_response(client_creds, tctx,
						   &flags,
						   chal,
						   NULL, /* server_timestamp */
						   names_blob,
						   &lm_resp, &nt_resp,
						   NULL, NULL);
	torture_assert_ntstatus_ok(tctx, status, "cli_credentials_get_ntlm_response failed");

	ninfo.lm.data = lm_resp.data;
	ninfo.lm.length = lm_resp.length;

	ninfo.nt.data = nt_resp.data;
	ninfo.nt.length = nt_resp.length;

	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.workstation.string = cli_credentials_get_workstation(server_creds);

	logon.network = &ninfo;

	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(server_creds);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = NetlogonNetworkInformation;
	r.in.logon = &logon;
	r.out.validation = &validation;
	r.out.authoritative = &authoritative;

	ZERO_STRUCT(auth2);
	netlogon_creds_client_authenticator(creds, &auth);

	r.in.validation_level = 3;

	status = dcerpc_netr_LogonSamLogon_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "LogonSamLogon failed");

	torture_assert(tctx, netlogon_creds_client_check(creds,
							 &r.out.return_authenticator->cred),
		       "Credential chaining failed");

	torture_assert_ntstatus_ok(tctx, r.out.result, "LogonSamLogon failed");

	status = make_user_info_dc_netlogon_validation(tmp_ctx,
						      ninfo.identity_info.account_name.string,
						      r.in.validation_level,
						      r.out.validation,
							  true, /* This user was authenticated */
						      &netlogon_user_info_dc);

	torture_assert_ntstatus_ok(tctx, status, "make_user_info_dc_netlogon_validation failed");

	torture_assert_str_equal(tctx, netlogon_user_info_dc->info->account_name == NULL ? "" : netlogon_user_info_dc->info->account_name,
				 kinit_session_info->info->account_name, "Account name differs for kinit-based PAC");
	torture_assert_str_equal(tctx,netlogon_user_info_dc->info->account_name == NULL ? "" : netlogon_user_info_dc->info->account_name,
				 s2u4self_session_info->info->account_name, "Account name differs for S2U4Self");
	torture_assert_str_equal(tctx, netlogon_user_info_dc->info->full_name == NULL ? "" : netlogon_user_info_dc->info->full_name, kinit_session_info->info->full_name, "Full name differs for kinit-based PAC");
	torture_assert_str_equal(tctx, netlogon_user_info_dc->info->full_name == NULL ? "" : netlogon_user_info_dc->info->full_name, s2u4self_session_info->info->full_name, "Full name differs for S2U4Self");
	torture_assert_int_equal(tctx, netlogon_user_info_dc->num_sids, kinit_session_info->torture->num_dc_sids, "Different numbers of domain groups for kinit-based PAC");
	torture_assert_int_equal(tctx, netlogon_user_info_dc->num_sids, s2u4self_session_info->torture->num_dc_sids, "Different numbers of domain groups for S2U4Self");

	builtin_domain = dom_sid_parse_talloc(tmp_ctx, SID_BUILTIN);

	for (i = 0; i < kinit_session_info->torture->num_dc_sids; i++) {
		torture_assert(tctx, dom_sid_equal(&netlogon_user_info_dc->sids[i], &kinit_session_info->torture->dc_sids[i]), "Different domain groups for kinit-based PAC");
		torture_assert(tctx, dom_sid_equal(&netlogon_user_info_dc->sids[i], &s2u4self_session_info->torture->dc_sids[i]), "Different domain groups for S2U4Self");
		torture_assert(tctx, !dom_sid_in_domain(builtin_domain, &s2u4self_session_info->torture->dc_sids[i]), "Returned BUILTIN domain in groups for S2U4Self");
		torture_assert(tctx, !dom_sid_in_domain(builtin_domain, &kinit_session_info->torture->dc_sids[i]), "Returned BUILTIN domain in groups kinit-based PAC");
		torture_assert(tctx, !dom_sid_in_domain(builtin_domain, &netlogon_user_info_dc->sids[i]), "Returned BUILTIN domian in groups from NETLOGON SamLogon reply");
	}

	return true;
}

static bool test_S2U4Self_bdc_arcfour(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      struct cli_credentials *credentials)
{
	return test_S2U4Self(tctx, p, credentials, SEC_CHAN_BDC,
			     TEST_MACHINE_NAME_S2U4SELF_BDC,
			     NETLOGON_NEG_AUTH2_ADS_FLAGS);
}

static bool test_S2U4Self_bdc_aes(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct cli_credentials *credentials)
{
	return test_S2U4Self(tctx, p, credentials, SEC_CHAN_BDC,
			     TEST_MACHINE_NAME_S2U4SELF_BDC,
			     NETLOGON_NEG_AUTH2_ADS_FLAGS | NETLOGON_NEG_SUPPORTS_AES);
}

static bool test_S2U4Self_workstation_arcfour(struct torture_context *tctx,
					      struct dcerpc_pipe *p,
					      struct cli_credentials *credentials)
{
	return test_S2U4Self(tctx, p, credentials, SEC_CHAN_WKSTA,
			     TEST_MACHINE_NAME_S2U4SELF_WKSTA,
			     NETLOGON_NEG_AUTH2_ADS_FLAGS);
}

static bool test_S2U4Self_workstation_aes(struct torture_context *tctx,
					  struct dcerpc_pipe *p,
					  struct cli_credentials *credentials)
{
	return test_S2U4Self(tctx, p, credentials, SEC_CHAN_WKSTA,
			     TEST_MACHINE_NAME_S2U4SELF_WKSTA,
			     NETLOGON_NEG_AUTH2_ADS_FLAGS | NETLOGON_NEG_SUPPORTS_AES);
}

struct torture_suite *torture_rpc_remote_pac(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "pac");
	struct torture_rpc_tcase *tcase;

	tcase = torture_suite_add_machine_bdc_rpc_iface_tcase(suite, "netr-bdc-arcfour",
							      &ndr_table_netlogon, TEST_MACHINE_NAME_BDC);
	torture_rpc_tcase_add_test_creds(tcase, "verify-sig-arcfour", test_PACVerify_bdc_arcfour);

	tcase = torture_suite_add_machine_bdc_rpc_iface_tcase(suite, "netr-bdc-aes",
							      &ndr_table_netlogon, TEST_MACHINE_NAME_BDC);
	torture_rpc_tcase_add_test_creds(tcase, "verify-sig-aes", test_PACVerify_bdc_aes);

	tcase = torture_suite_add_machine_workstation_rpc_iface_tcase(suite, "netr-mem-arcfour",
								      &ndr_table_netlogon, TEST_MACHINE_NAME_WKSTA);
	torture_rpc_tcase_add_test_creds(tcase, "verify-sig-arcfour", test_PACVerify_workstation_arcfour);

	tcase = torture_suite_add_machine_workstation_rpc_iface_tcase(suite, "netr-mem-aes",
								      &ndr_table_netlogon, TEST_MACHINE_NAME_WKSTA);
	torture_rpc_tcase_add_test_creds(tcase, "verify-sig-aes", test_PACVerify_workstation_aes);

	tcase = torture_suite_add_machine_workstation_rpc_iface_tcase(suite, "netlogon-member-des",
								      &ndr_table_netlogon, TEST_MACHINE_NAME_WKSTA_DES);
	torture_rpc_tcase_add_test_join(tcase, "verify-sig", test_PACVerify_workstation_des);

	tcase = torture_suite_add_machine_bdc_rpc_iface_tcase(suite, "netr-bdc-arcfour",
							      &ndr_table_netlogon, TEST_MACHINE_NAME_S2U4SELF_BDC);
	torture_rpc_tcase_add_test_creds(tcase, "s2u4self-arcfour", test_S2U4Self_bdc_arcfour);

	tcase = torture_suite_add_machine_bdc_rpc_iface_tcase(suite, "netr-bcd-aes",
							      &ndr_table_netlogon, TEST_MACHINE_NAME_S2U4SELF_BDC);
	torture_rpc_tcase_add_test_creds(tcase, "s2u4self-aes", test_S2U4Self_bdc_aes);

	tcase = torture_suite_add_machine_workstation_rpc_iface_tcase(suite, "netr-mem-arcfour",
								      &ndr_table_netlogon, TEST_MACHINE_NAME_S2U4SELF_WKSTA);
	torture_rpc_tcase_add_test_creds(tcase, "s2u4self-arcfour", test_S2U4Self_workstation_arcfour);

	tcase = torture_suite_add_machine_workstation_rpc_iface_tcase(suite, "netr-mem-aes",
								      &ndr_table_netlogon, TEST_MACHINE_NAME_S2U4SELF_WKSTA);
	torture_rpc_tcase_add_test_creds(tcase, "s2u4self-aes", test_S2U4Self_workstation_aes);

	return suite;
}
