/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "../libds/common/flags.h"
#include <ldb.h>
#include "auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "kdc/samba_kdc.h"
#include "kdc/pac-glue.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "auth/kerberos/pac_utils.h"

static
NTSTATUS samba_get_logon_info_pac_blob(TALLOC_CTX *mem_ctx,
				       const struct auth_user_info_dc *info,
				       DATA_BLOB *pac_data)
{
	struct netr_SamInfo3 *info3;
	union PAC_INFO pac_info;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	ZERO_STRUCT(pac_info);

	*pac_data = data_blob_null;

	nt_status = auth_convert_user_info_dc_saminfo3(mem_ctx, info, &info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Getting Samba info failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	pac_info.logon_info.info = talloc_zero(mem_ctx, struct PAC_LOGON_INFO);
	if (!pac_info.logon_info.info) {
		return NT_STATUS_NO_MEMORY;
	}

	pac_info.logon_info.info->info3 = *info3;

	ndr_err = ndr_push_union_blob(pac_data, mem_ctx, &pac_info,
				      PAC_TYPE_LOGON_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC_LOGON_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_OK;
}

static
NTSTATUS samba_get_upn_info_pac_blob(TALLOC_CTX *mem_ctx,
				     const struct auth_user_info_dc *info,
				     DATA_BLOB *upn_data)
{
	union PAC_INFO pac_upn;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	ZERO_STRUCT(pac_upn);

	*upn_data = data_blob_null;

	pac_upn.upn_dns_info.upn_name = info->info->user_principal_name;
	pac_upn.upn_dns_info.dns_domain_name = strupper_talloc(mem_ctx,
						info->info->dns_domain_name);
	if (pac_upn.upn_dns_info.dns_domain_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	if (info->info->user_principal_constructed) {
		pac_upn.upn_dns_info.flags |= PAC_UPN_DNS_FLAG_CONSTRUCTED;
	}

	ndr_err = ndr_push_union_blob(upn_data, mem_ctx, &pac_upn,
				      PAC_TYPE_UPN_DNS_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC UPN_DNS_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_OK;
}

static
NTSTATUS samba_get_cred_info_ndr_blob(TALLOC_CTX *mem_ctx,
				      const struct ldb_message *msg,
				      DATA_BLOB *cred_blob)
{
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;
	int ret;
	static const struct samr_Password zero_hash;
	struct samr_Password *lm_hash = NULL;
	struct samr_Password *nt_hash = NULL;
	struct PAC_CREDENTIAL_NTLM_SECPKG ntlm_secpkg = {
		.version = 0,
	};
	DATA_BLOB ntlm_blob = data_blob_null;
	struct PAC_CREDENTIAL_SUPPLEMENTAL_SECPKG secpkgs[1] = {{
		.credential_size = 0,
	}};
	struct PAC_CREDENTIAL_DATA cred_data = {
		.credential_count = 0,
	};
	struct PAC_CREDENTIAL_DATA_NDR cred_ndr;

	ZERO_STRUCT(cred_ndr);

	*cred_blob = data_blob_null;

	lm_hash = samdb_result_hash(mem_ctx, msg, "dBCSPwd");
	if (lm_hash != NULL) {
		ret = memcmp(lm_hash->hash, zero_hash.hash, 16);
		if (ret == 0) {
			lm_hash = NULL;
		}
	}
	if (lm_hash != NULL) {
		DEBUG(5, ("Passing LM password hash through credentials set\n"));
		ntlm_secpkg.flags |= PAC_CREDENTIAL_NTLM_HAS_LM_HASH;
		ntlm_secpkg.lm_password = *lm_hash;
		ZERO_STRUCTP(lm_hash);
		TALLOC_FREE(lm_hash);
	}

	nt_hash = samdb_result_hash(mem_ctx, msg, "unicodePwd");
	if (nt_hash != NULL) {
		ret = memcmp(nt_hash->hash, zero_hash.hash, 16);
		if (ret == 0) {
			nt_hash = NULL;
		}
	}
	if (nt_hash != NULL) {
		DEBUG(5, ("Passing LM password hash through credentials set\n"));
		ntlm_secpkg.flags |= PAC_CREDENTIAL_NTLM_HAS_NT_HASH;
		ntlm_secpkg.nt_password = *nt_hash;
		ZERO_STRUCTP(nt_hash);
		TALLOC_FREE(nt_hash);
	}

	if (ntlm_secpkg.flags == 0) {
		return NT_STATUS_OK;
	}

#ifdef DEBUG_PASSWORD
	if (DEBUGLVL(11)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_NTLM_SECPKG, &ntlm_secpkg);
	}
#endif

	ndr_err = ndr_push_struct_blob(&ntlm_blob, mem_ctx, &ntlm_secpkg,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_NTLM_SECPKG);
	ZERO_STRUCT(ntlm_secpkg);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC_CREDENTIAL_NTLM_SECPKG (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	DEBUG(10, ("NTLM credential BLOB (len %zu) for user\n",
		  ntlm_blob.length));
	dump_data_pw("PAC_CREDENTIAL_NTLM_SECPKG",
		     ntlm_blob.data, ntlm_blob.length);

	secpkgs[0].package_name.string = discard_const_p(char, "NTLM");
	secpkgs[0].credential_size = ntlm_blob.length;
	secpkgs[0].credential = ntlm_blob.data;

	cred_data.credential_count = ARRAY_SIZE(secpkgs);
	cred_data.credentials = secpkgs;

#ifdef DEBUG_PASSWORD
	if (DEBUGLVL(11)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_DATA, &cred_data);
	}
#endif

	cred_ndr.ctr.data = &cred_data;

#ifdef DEBUG_PASSWORD
	if (DEBUGLVL(11)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_DATA_NDR, &cred_ndr);
	}
#endif

	ndr_err = ndr_push_struct_blob(cred_blob, mem_ctx, &cred_ndr,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_DATA_NDR);
	data_blob_clear(&ntlm_blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC_CREDENTIAL_DATA_NDR (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	DEBUG(10, ("Created credential BLOB (len %zu) for user\n",
		  cred_blob->length));
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_blob->data, cred_blob->length);

	return NT_STATUS_OK;
}

#ifdef SAMBA4_USES_HEIMDAL
krb5_error_code samba_kdc_encrypt_pac_credentials(krb5_context context,
						  const krb5_keyblock *pkreplykey,
						  const DATA_BLOB *cred_ndr_blob,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *cred_info_blob)
{
	krb5_crypto cred_crypto;
	krb5_enctype cred_enctype;
	krb5_data cred_ndr_crypt;
	struct PAC_CREDENTIAL_INFO pac_cred_info = { .version = 0, };
	krb5_error_code ret;
	const char *krb5err;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	*cred_info_blob = data_blob_null;

	ret = krb5_crypto_init(context, pkreplykey, ETYPE_NULL,
			       &cred_crypto);
	if (ret != 0) {
		krb5err = krb5_get_error_message(context, ret);
		DEBUG(1, ("Failed initializing cred data crypto: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return ret;
	}

	ret = krb5_crypto_getenctype(context, cred_crypto, &cred_enctype);
	if (ret != 0) {
		DEBUG(1, ("Failed getting crypto type for key\n"));
		krb5_crypto_destroy(context, cred_crypto);
		return ret;
	}

	DEBUG(10, ("Plain cred_ndr_blob (len %zu)\n",
		  cred_ndr_blob->length));
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_ndr_blob->data, cred_ndr_blob->length);

	ret = krb5_encrypt(context, cred_crypto,
			   KRB5_KU_OTHER_ENCRYPTED,
			   cred_ndr_blob->data, cred_ndr_blob->length,
			   &cred_ndr_crypt);
	krb5_crypto_destroy(context, cred_crypto);
	if (ret != 0) {
		krb5err = krb5_get_error_message(context, ret);
		DEBUG(1, ("Failed crypt of cred data: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return ret;
	}

	pac_cred_info.encryption_type = cred_enctype;
	pac_cred_info.encrypted_data.length = cred_ndr_crypt.length;
	pac_cred_info.encrypted_data.data = (uint8_t *)cred_ndr_crypt.data;

	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_INFO, &pac_cred_info);
	}

	ndr_err = ndr_push_struct_blob(cred_info_blob, mem_ctx, &pac_cred_info,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_INFO);
	krb5_data_free(&cred_ndr_crypt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC_CREDENTIAL_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return KRB5KDC_ERR_SVC_UNAVAILABLE;
	}

	DEBUG(10, ("Encrypted credential BLOB (len %zu) with alg %d\n",
		  cred_info_blob->length, (int)pac_cred_info.encryption_type));
	dump_data_pw("PAC_CREDENTIAL_INFO",
		      cred_info_blob->data, cred_info_blob->length);

	return 0;
}
#else /* SAMBA4_USES_HEIMDAL */
krb5_error_code samba_kdc_encrypt_pac_credentials(krb5_context context,
						  const krb5_keyblock *pkreplykey,
						  const DATA_BLOB *cred_ndr_blob,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *cred_info_blob)
{
	krb5_key cred_key;
	krb5_enctype cred_enctype;
	struct PAC_CREDENTIAL_INFO pac_cred_info = { .version = 0, };
	krb5_error_code code;
	const char *krb5err;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;
	krb5_data cred_ndr_data;
	krb5_enc_data cred_ndr_crypt;
	size_t enc_len = 0;

	*cred_info_blob = data_blob_null;

	code = krb5_k_create_key(context,
				 pkreplykey,
				 &cred_key);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DEBUG(1, ("Failed initializing cred data crypto: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return code;
	}

	cred_enctype = krb5_k_key_enctype(context, cred_key);

	DEBUG(10, ("Plain cred_ndr_blob (len %zu)\n",
		  cred_ndr_blob->length));
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_ndr_blob->data, cred_ndr_blob->length);

	pac_cred_info.encryption_type = cred_enctype;

	cred_ndr_data.magic = 0;
	cred_ndr_data.data = (char *)cred_ndr_blob->data;
	cred_ndr_data.length = cred_ndr_blob->length;

	code = krb5_c_encrypt_length(context,
				     cred_enctype,
				     cred_ndr_data.length,
				     &enc_len);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DEBUG(1, ("Failed initializing cred data crypto: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return code;
	}

	pac_cred_info.encrypted_data = data_blob_talloc_zero(mem_ctx, enc_len);
	if (pac_cred_info.encrypted_data.data == NULL) {
		DBG_ERR("Out of memory\n");
		return ENOMEM;
	}

	cred_ndr_crypt.ciphertext.length = enc_len;
	cred_ndr_crypt.ciphertext.data = (char *)pac_cred_info.encrypted_data.data;

	code = krb5_k_encrypt(context,
			      cred_key,
			      KRB5_KU_OTHER_ENCRYPTED,
			      NULL,
			      &cred_ndr_data,
			      &cred_ndr_crypt);
	krb5_k_free_key(context, cred_key);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DEBUG(1, ("Failed crypt of cred data: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return code;
	}

	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_INFO, &pac_cred_info);
	}

	ndr_err = ndr_push_struct_blob(cred_info_blob, mem_ctx, &pac_cred_info,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_INFO);
	TALLOC_FREE(pac_cred_info.encrypted_data.data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC_CREDENTIAL_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return KRB5KDC_ERR_SVC_UNAVAILABLE;
	}

	DEBUG(10, ("Encrypted credential BLOB (len %zu) with alg %d\n",
		  cred_info_blob->length, (int)pac_cred_info.encryption_type));
	dump_data_pw("PAC_CREDENTIAL_INFO",
		      cred_info_blob->data, cred_info_blob->length);

	return 0;
}
#endif /* SAMBA4_USES_HEIMDAL */


krb5_error_code samba_make_krb5_pac(krb5_context context,
				    const DATA_BLOB *logon_blob,
				    const DATA_BLOB *cred_blob,
				    const DATA_BLOB *upn_blob,
				    const DATA_BLOB *deleg_blob,
				    krb5_pac *pac)
{
	krb5_data logon_data;
	krb5_data cred_data;
	krb5_data upn_data;
	krb5_data deleg_data;
	krb5_data null_data;
	krb5_error_code ret;

	ZERO_STRUCT(null_data);

	/* The user account may be set not to want the PAC */
	if (logon_blob == NULL) {
		return 0;
	}

	ret = smb_krb5_copy_data_contents(&logon_data,
					  logon_blob->data,
					  logon_blob->length);
	if (ret != 0) {
		return ret;
	}

	ZERO_STRUCT(cred_data);
	if (cred_blob != NULL) {
		ret = smb_krb5_copy_data_contents(&cred_data,
						  cred_blob->data,
						  cred_blob->length);
		if (ret != 0) {
			smb_krb5_free_data_contents(context, &logon_data);
			return ret;
		}
	}

	ZERO_STRUCT(upn_data);
	if (upn_blob != NULL) {
		ret = smb_krb5_copy_data_contents(&upn_data,
						  upn_blob->data,
						  upn_blob->length);
		if (ret != 0) {
			smb_krb5_free_data_contents(context, &logon_data);
			smb_krb5_free_data_contents(context, &cred_data);
			return ret;
		}
	}

	ZERO_STRUCT(deleg_data);
	if (deleg_blob != NULL) {
		ret = smb_krb5_copy_data_contents(&deleg_data,
						  deleg_blob->data,
						  deleg_blob->length);
		if (ret != 0) {
			smb_krb5_free_data_contents(context, &logon_data);
			smb_krb5_free_data_contents(context, &cred_data);
			smb_krb5_free_data_contents(context, &upn_data);
			return ret;
		}
	}

	ret = krb5_pac_init(context, pac);
	if (ret != 0) {
		smb_krb5_free_data_contents(context, &logon_data);
		smb_krb5_free_data_contents(context, &cred_data);
		smb_krb5_free_data_contents(context, &upn_data);
		smb_krb5_free_data_contents(context, &deleg_data);
		return ret;
	}

	ret = krb5_pac_add_buffer(context, *pac, PAC_TYPE_LOGON_INFO, &logon_data);
	smb_krb5_free_data_contents(context, &logon_data);
	if (ret != 0) {
		smb_krb5_free_data_contents(context, &upn_data);
		smb_krb5_free_data_contents(context, &cred_data);
		smb_krb5_free_data_contents(context, &deleg_data);
		return ret;
	}

	if (cred_blob != NULL) {
		ret = krb5_pac_add_buffer(context, *pac,
					  PAC_TYPE_CREDENTIAL_INFO,
					  &cred_data);
		smb_krb5_free_data_contents(context, &cred_data);
		if (ret != 0) {
			smb_krb5_free_data_contents(context, &upn_data);
			smb_krb5_free_data_contents(context, &deleg_data);
			return ret;
		}
	}

	/*
	 * null_data will be filled by the generic KDC code in the caller
	 * here we just add it in order to have it before
	 * PAC_TYPE_UPN_DNS_INFO
	 */
	ret = krb5_pac_add_buffer(context, *pac,
				  PAC_TYPE_LOGON_NAME,
				  &null_data);
	if (ret != 0) {
		smb_krb5_free_data_contents(context, &upn_data);
		smb_krb5_free_data_contents(context, &deleg_data);
		return ret;
	}

	if (upn_blob != NULL) {
		ret = krb5_pac_add_buffer(context, *pac,
					  PAC_TYPE_UPN_DNS_INFO,
					  &upn_data);
		smb_krb5_free_data_contents(context, &upn_data);
		if (ret != 0) {
			smb_krb5_free_data_contents(context, &deleg_data);
			return ret;
		}
	}

	if (deleg_blob != NULL) {
		ret = krb5_pac_add_buffer(context, *pac,
					  PAC_TYPE_CONSTRAINED_DELEGATION,
					  &deleg_data);
		smb_krb5_free_data_contents(context, &deleg_data);
		if (ret != 0) {
			return ret;
		}
	}

	return ret;
}

bool samba_princ_needs_pac(struct samba_kdc_entry *skdc_entry)
{

	uint32_t userAccountControl;

	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(skdc_entry->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		return false;
	}

	return true;
}

/* Was the krbtgt in this DB (ie, should we check the incoming signature) and was it an RODC */
int samba_krbtgt_is_in_db(struct samba_kdc_entry *p,
			  bool *is_in_db,
			  bool *is_untrusted)
{
	NTSTATUS status;
	int rodc_krbtgt_number, trust_direction;
	uint32_t rid;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	if (!mem_ctx) {
		return ENOMEM;
	}
	
	trust_direction = ldb_msg_find_attr_as_int(p->msg, "trustDirection", 0);

	if (trust_direction != 0) {
		/* Domain trust - we cannot check the sig, but we trust it for a correct PAC
		   
		   This is exactly where we should flag for SID
		   validation when we do inter-foreest trusts
		 */
		talloc_free(mem_ctx);
		*is_untrusted = false;
		*is_in_db = false;
		return 0;
	}

	/* The lack of password controls etc applies to krbtgt by
	 * virtue of being that particular RID */
	status = dom_sid_split_rid(NULL, samdb_result_dom_sid(mem_ctx, p->msg, "objectSid"), NULL, &rid);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return EINVAL;
	}

	rodc_krbtgt_number = ldb_msg_find_attr_as_int(p->msg, "msDS-SecondaryKrbTgtNumber", -1);

	if (p->kdc_db_ctx->my_krbtgt_number == 0) {
		if (rid == DOMAIN_RID_KRBTGT) {
			*is_untrusted = false;
			*is_in_db = true;
			talloc_free(mem_ctx);
			return 0;
		} else if (rodc_krbtgt_number != -1) {
			*is_in_db = true;
			*is_untrusted = true;
			talloc_free(mem_ctx);
			return 0;
		}
	} else if ((rid != DOMAIN_RID_KRBTGT) && (rodc_krbtgt_number == p->kdc_db_ctx->my_krbtgt_number)) {
		talloc_free(mem_ctx);
		*is_untrusted = false;
		*is_in_db = true;
		return 0;
	} else if (rid == DOMAIN_RID_KRBTGT) {
		/* krbtgt viewed from an RODC */
		talloc_free(mem_ctx);
		*is_untrusted = false;
		*is_in_db = false;
		return 0;
	}

	/* Another RODC */
	talloc_free(mem_ctx);
	*is_untrusted = true;
	*is_in_db = false;
	return 0;
}

NTSTATUS samba_kdc_get_pac_blobs(TALLOC_CTX *mem_ctx,
				 struct samba_kdc_entry *p,
				 DATA_BLOB **_logon_info_blob,
				 DATA_BLOB **_cred_ndr_blob,
				 DATA_BLOB **_upn_info_blob)
{
	struct auth_user_info_dc *user_info_dc;
	DATA_BLOB *logon_blob = NULL;
	DATA_BLOB *cred_blob = NULL;
	DATA_BLOB *upn_blob = NULL;
	NTSTATUS nt_status;

	*_logon_info_blob = NULL;
	if (_cred_ndr_blob != NULL) {
		*_cred_ndr_blob = NULL;
	}
	*_upn_info_blob = NULL;

	/* The user account may be set not to want the PAC */
	if ( ! samba_princ_needs_pac(p)) {
		return NT_STATUS_OK;
	}

	logon_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (logon_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (_cred_ndr_blob != NULL) {
		cred_blob = talloc_zero(mem_ctx, DATA_BLOB);
		if (cred_blob == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	upn_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (upn_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = authsam_make_user_info_dc(mem_ctx, p->kdc_db_ctx->samdb,
					     lpcfg_netbios_name(p->kdc_db_ctx->lp_ctx),
					     lpcfg_sam_name(p->kdc_db_ctx->lp_ctx),
					     lpcfg_sam_dnsname(p->kdc_db_ctx->lp_ctx),
					     p->realm_dn,
					     p->msg,
					     data_blob(NULL, 0),
					     data_blob(NULL, 0),
					     &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	nt_status = samba_get_logon_info_pac_blob(logon_blob,
						  user_info_dc,
						  logon_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC LOGON INFO failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	if (cred_blob != NULL) {
		nt_status = samba_get_cred_info_ndr_blob(cred_blob,
							 p->msg,
							 cred_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Building PAC CRED INFO failed: %s\n",
				  nt_errstr(nt_status)));
			return nt_status;
		}
	}

	nt_status = samba_get_upn_info_pac_blob(upn_blob,
						user_info_dc,
						upn_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC UPN INFO failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	TALLOC_FREE(user_info_dc);
	*_logon_info_blob = logon_blob;
	if (_cred_ndr_blob != NULL) {
		*_cred_ndr_blob = cred_blob;
	}
	*_upn_info_blob = upn_blob;
	return NT_STATUS_OK;
}

NTSTATUS samba_kdc_get_pac_blob(TALLOC_CTX *mem_ctx,
				struct samba_kdc_entry *p,
				DATA_BLOB **_logon_info_blob)
{
	NTSTATUS nt_status;
	DATA_BLOB *upn_blob = NULL;

	nt_status = samba_kdc_get_pac_blobs(mem_ctx, p,
					    _logon_info_blob,
					    NULL, /* cred_blob */
					    &upn_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	TALLOC_FREE(upn_blob);
	return NT_STATUS_OK;
}

NTSTATUS samba_kdc_update_pac_blob(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   const krb5_pac pac, DATA_BLOB *pac_blob,
				   struct PAC_SIGNATURE_DATA *pac_srv_sig,
				   struct PAC_SIGNATURE_DATA *pac_kdc_sig)
{
	struct auth_user_info_dc *user_info_dc;
	krb5_error_code ret;
	NTSTATUS nt_status;

	ret = kerberos_pac_to_user_info_dc(mem_ctx, pac,
					   context, &user_info_dc, pac_srv_sig, pac_kdc_sig);
	if (ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx, 
						  user_info_dc, pac_blob);

	return nt_status;
}

NTSTATUS samba_kdc_update_delegation_info_blob(TALLOC_CTX *mem_ctx,
				krb5_context context,
				const krb5_pac pac,
				const krb5_principal server_principal,
				const krb5_principal proxy_principal,
				DATA_BLOB *new_blob)
{
	krb5_data old_data;
	DATA_BLOB old_blob;
	krb5_error_code ret;
	NTSTATUS nt_status;
	enum ndr_err_code ndr_err;
	union PAC_INFO info;
	struct PAC_CONSTRAINED_DELEGATION _d;
	struct PAC_CONSTRAINED_DELEGATION *d = NULL;
	char *server = NULL;
	char *proxy = NULL;
	uint32_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_CONSTRAINED_DELEGATION, &old_data);
	if (ret == ENOENT) {
		ZERO_STRUCT(old_data);
	} else if (ret) {
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	old_blob.length = old_data.length;
	old_blob.data = (uint8_t *)old_data.data;

	ZERO_STRUCT(info);
	if (old_blob.length > 0) {
		ndr_err = ndr_pull_union_blob(&old_blob, mem_ctx,
				&info, PAC_TYPE_CONSTRAINED_DELEGATION,
				(ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			smb_krb5_free_data_contents(context, &old_data);
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
			talloc_free(tmp_ctx);
			return nt_status;
		}
	} else {
		ZERO_STRUCT(_d);
		info.constrained_delegation.info = &_d;
	}
	smb_krb5_free_data_contents(context, &old_data);

	ret = krb5_unparse_name(context, server_principal, &server);
	if (ret) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = krb5_unparse_name_flags(context, proxy_principal,
				      KRB5_PRINCIPAL_UNPARSE_NO_REALM, &proxy);
	if (ret) {
		SAFE_FREE(server);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	d = info.constrained_delegation.info;
	i = d->num_transited_services;
	d->proxy_target.string = server;
	d->transited_services = talloc_realloc(mem_ctx, d->transited_services,
					       struct lsa_String, i + 1);
	d->transited_services[i].string = proxy;
	d->num_transited_services = i + 1;

	ndr_err = ndr_push_union_blob(new_blob, mem_ctx,
				&info, PAC_TYPE_CONSTRAINED_DELEGATION,
				(ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	SAFE_FREE(server);
	SAFE_FREE(proxy);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		smb_krb5_free_data_contents(context, &old_data);
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/* function to map policy errors */
krb5_error_code samba_kdc_map_policy_err(NTSTATUS nt_status)
{
	krb5_error_code ret;

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_MUST_CHANGE))
		ret = KRB5KDC_ERR_KEY_EXP;
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_EXPIRED))
		ret = KRB5KDC_ERR_KEY_EXP;
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_EXPIRED))
		ret = KRB5KDC_ERR_CLIENT_REVOKED;
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_DISABLED))
		ret = KRB5KDC_ERR_CLIENT_REVOKED;
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_LOGON_HOURS))
		ret = KRB5KDC_ERR_CLIENT_REVOKED;
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_LOCKED_OUT))
		ret = KRB5KDC_ERR_CLIENT_REVOKED;
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_WORKSTATION))
		ret = KRB5KDC_ERR_POLICY;
	else
		ret = KRB5KDC_ERR_POLICY;

	return ret;
}

/* Given a kdc entry, consult the account_ok routine in auth/auth_sam.c
 * for consistency */
NTSTATUS samba_kdc_check_client_access(struct samba_kdc_entry *kdc_entry,
				       const char *client_name,
				       const char *workstation,
				       bool password_change)
{
	TALLOC_CTX *tmp_ctx;
	NTSTATUS nt_status;

	tmp_ctx = talloc_named(NULL, 0, "samba_kdc_check_client_access");
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* we allow all kinds of trusts here */
	nt_status = authsam_account_ok(tmp_ctx,
				       kdc_entry->kdc_db_ctx->samdb,
				       MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT |
				       MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT,
				       kdc_entry->realm_dn, kdc_entry->msg,
				       workstation, client_name,
				       true, password_change);

	talloc_free(tmp_ctx);
	return nt_status;
}
