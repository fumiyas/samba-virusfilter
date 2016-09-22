/* need access mask/acl implementation */

/* 
   Unix SMB/CIFS implementation.

   endpoint server for the lsarpc pipe

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2008

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

#include "rpc_server/lsa/lsa.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "../lib/crypto/crypto.h"
#include "lib/util/tsort.h"
#include "dsdb/common/util.h"
#include "libcli/security/session.h"
#include "libcli/lsarpc/util_lsarpc.h"
#include "lib/messaging/irpc.h"
#include "libds/common/roles.h"

#define DCESRV_INTERFACE_LSARPC_BIND(call, iface) \
       dcesrv_interface_lsarpc_bind(call, iface)
static NTSTATUS dcesrv_interface_lsarpc_bind(struct dcesrv_call_state *dce_call,
					     const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_reject_connect(dce_call, iface);
}

/*
  this type allows us to distinguish handle types
*/

/*
  state associated with a lsa_OpenAccount() operation
*/
struct lsa_account_state {
	struct lsa_policy_state *policy;
	uint32_t access_mask;
	struct dom_sid *account_sid;
};


/*
  state associated with a lsa_OpenSecret() operation
*/
struct lsa_secret_state {
	struct lsa_policy_state *policy;
	uint32_t access_mask;
	struct ldb_dn *secret_dn;
	struct ldb_context *sam_ldb;
	bool global;
};

/*
  state associated with a lsa_OpenTrustedDomain() operation
*/
struct lsa_trusted_domain_state {
	struct lsa_policy_state *policy;
	uint32_t access_mask;
	struct ldb_dn *trusted_domain_dn;
	struct ldb_dn *trusted_domain_user_dn;
};

/*
  this is based on the samba3 function make_lsa_object_sd()
  It uses the same logic, but with samba4 helper functions
 */
static NTSTATUS dcesrv_build_lsa_sd(TALLOC_CTX *mem_ctx,
				    struct security_descriptor **sd,
				    struct dom_sid *sid,
				    uint32_t sid_access)
{
	NTSTATUS status;
	uint32_t rid;
	struct dom_sid *domain_sid, *domain_admins_sid;
	const char *domain_admins_sid_str, *sidstr;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	status = dom_sid_split_rid(tmp_ctx, sid, &domain_sid, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	domain_admins_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ADMINS);
	if (domain_admins_sid == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	domain_admins_sid_str = dom_sid_string(tmp_ctx, domain_admins_sid);
	if (domain_admins_sid_str == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	sidstr = dom_sid_string(tmp_ctx, sid);
	if (sidstr == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	*sd = security_descriptor_dacl_create(mem_ctx,
					      0, sidstr, NULL,

					      SID_WORLD,
					      SEC_ACE_TYPE_ACCESS_ALLOWED,
					      SEC_GENERIC_EXECUTE | SEC_GENERIC_READ, 0,

					      SID_BUILTIN_ADMINISTRATORS,
					      SEC_ACE_TYPE_ACCESS_ALLOWED,
					      SEC_GENERIC_ALL, 0,

					      SID_BUILTIN_ACCOUNT_OPERATORS,
					      SEC_ACE_TYPE_ACCESS_ALLOWED,
					      SEC_GENERIC_ALL, 0,

					      domain_admins_sid_str,
					      SEC_ACE_TYPE_ACCESS_ALLOWED,
					      SEC_GENERIC_ALL, 0,

					      sidstr,
					      SEC_ACE_TYPE_ACCESS_ALLOWED,
					      sid_access, 0,

					      NULL);
	talloc_free(tmp_ctx);

	NT_STATUS_HAVE_NO_MEMORY(*sd);

	return NT_STATUS_OK;
}


static NTSTATUS dcesrv_lsa_EnumAccountRights(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx,
				      struct lsa_EnumAccountRights *r);

static NTSTATUS dcesrv_lsa_AddRemoveAccountRights(struct dcesrv_call_state *dce_call,
					   TALLOC_CTX *mem_ctx,
					   struct lsa_policy_state *state,
					   int ldb_flag,
					   struct dom_sid *sid,
					   const struct lsa_RightSet *rights);

/*
  lsa_Close
*/
static NTSTATUS dcesrv_lsa_Close(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			  struct lsa_Close *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	struct dcesrv_handle *h;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	talloc_free(h);

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/*
  lsa_Delete
*/
static NTSTATUS dcesrv_lsa_Delete(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			   struct lsa_Delete *r)
{
	return NT_STATUS_NOT_SUPPORTED;
}


/*
  lsa_DeleteObject
*/
static NTSTATUS dcesrv_lsa_DeleteObject(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_DeleteObject *r)
{
	struct dcesrv_handle *h;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	if (h->wire_handle.handle_type == LSA_HANDLE_SECRET) {
		struct lsa_secret_state *secret_state = h->data;

		/* Ensure user is permitted to delete this... */
		switch (security_session_user_level(dce_call->conn->auth_state.session_info, NULL))
		{
		case SECURITY_SYSTEM:
		case SECURITY_ADMINISTRATOR:
			break;
		default:
			/* Users and anonymous are not allowed to delete things */
			return NT_STATUS_ACCESS_DENIED;
		}

		ret = ldb_delete(secret_state->sam_ldb,
				 secret_state->secret_dn);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_INVALID_HANDLE;
		}

		ZERO_STRUCTP(r->out.handle);

		return NT_STATUS_OK;

	} else if (h->wire_handle.handle_type == LSA_HANDLE_TRUSTED_DOMAIN) {
		struct lsa_trusted_domain_state *trusted_domain_state =
			talloc_get_type(h->data, struct lsa_trusted_domain_state);
		ret = ldb_transaction_start(trusted_domain_state->policy->sam_ldb);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ret = ldb_delete(trusted_domain_state->policy->sam_ldb,
				 trusted_domain_state->trusted_domain_dn);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(trusted_domain_state->policy->sam_ldb);
			return NT_STATUS_INVALID_HANDLE;
		}

		if (trusted_domain_state->trusted_domain_user_dn) {
			ret = ldb_delete(trusted_domain_state->policy->sam_ldb,
					 trusted_domain_state->trusted_domain_user_dn);
			if (ret != LDB_SUCCESS) {
				ldb_transaction_cancel(trusted_domain_state->policy->sam_ldb);
				return NT_STATUS_INVALID_HANDLE;
			}
		}

		ret = ldb_transaction_commit(trusted_domain_state->policy->sam_ldb);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ZERO_STRUCTP(r->out.handle);

		return NT_STATUS_OK;

	} else if (h->wire_handle.handle_type == LSA_HANDLE_ACCOUNT) {
		struct lsa_RightSet *rights;
		struct lsa_account_state *astate;
		struct lsa_EnumAccountRights r2;
		NTSTATUS status;

		rights = talloc(mem_ctx, struct lsa_RightSet);

		DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

		astate = h->data;

		r2.in.handle = &astate->policy->handle->wire_handle;
		r2.in.sid = astate->account_sid;
		r2.out.rights = rights;

		/* dcesrv_lsa_EnumAccountRights takes a LSA_HANDLE_POLICY,
		   but we have a LSA_HANDLE_ACCOUNT here, so this call
		   will always fail */
		status = dcesrv_lsa_EnumAccountRights(dce_call, mem_ctx, &r2);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			return NT_STATUS_OK;
		}

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy,
						    LDB_FLAG_MOD_DELETE, astate->account_sid,
						    r2.out.rights);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			return NT_STATUS_OK;
		}

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		ZERO_STRUCTP(r->out.handle);

		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_HANDLE;
}


/*
  lsa_EnumPrivs
*/
static NTSTATUS dcesrv_lsa_EnumPrivs(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct lsa_EnumPrivs *r)
{
	struct dcesrv_handle *h;
	uint32_t i;
	enum sec_privilege priv;
	const char *privname;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	i = *r->in.resume_handle;

	while (((priv = sec_privilege_from_index(i)) != SEC_PRIV_INVALID) &&
	       r->out.privs->count < r->in.max_count) {
		struct lsa_PrivEntry *e;
		privname = sec_privilege_name(priv);
		r->out.privs->privs = talloc_realloc(r->out.privs,
						       r->out.privs->privs,
						       struct lsa_PrivEntry,
						       r->out.privs->count+1);
		if (r->out.privs->privs == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		e = &r->out.privs->privs[r->out.privs->count];
		e->luid.low = priv;
		e->luid.high = 0;
		e->name.string = privname;
		r->out.privs->count++;
		i++;
	}

	*r->out.resume_handle = i;

	return NT_STATUS_OK;
}


/*
  lsa_QuerySecObj
*/
static NTSTATUS dcesrv_lsa_QuerySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct lsa_QuerySecurity *r)
{
	struct dcesrv_handle *h;
	const struct security_descriptor *sd = NULL;
	uint32_t access_granted = 0;
	struct sec_desc_buf *sdbuf = NULL;
	NTSTATUS status;
	struct dom_sid *sid;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	sid = &dce_call->conn->auth_state.session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

	if (h->wire_handle.handle_type == LSA_HANDLE_POLICY) {
		struct lsa_policy_state *pstate = h->data;

		sd = pstate->sd;
		access_granted = pstate->access_mask;

	} else if (h->wire_handle.handle_type == LSA_HANDLE_ACCOUNT) {
		struct lsa_account_state *astate = h->data;
		struct security_descriptor *_sd = NULL;

		status = dcesrv_build_lsa_sd(mem_ctx, &_sd, sid,
					     LSA_ACCOUNT_ALL_ACCESS);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		sd = _sd;
		access_granted = astate->access_mask;
	} else {
		return NT_STATUS_INVALID_HANDLE;
	}

	sdbuf = talloc_zero(mem_ctx, struct sec_desc_buf);
	if (sdbuf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = security_descriptor_for_client(sdbuf, sd, r->in.sec_info,
						access_granted, &sdbuf->sd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*r->out.sdbuf = sdbuf;

	return NT_STATUS_OK;
}


/*
  lsa_SetSecObj
*/
static NTSTATUS dcesrv_lsa_SetSecObj(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct lsa_SetSecObj *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_ChangePassword
*/
static NTSTATUS dcesrv_lsa_ChangePassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct lsa_ChangePassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  dssetup_DsRoleGetPrimaryDomainInformation

  This is not an LSA call, but is the only call left on the DSSETUP
  pipe (after the pipe was truncated), and needs lsa_get_policy_state
*/
static WERROR dcesrv_dssetup_DsRoleGetPrimaryDomainInformation(struct dcesrv_call_state *dce_call,
						 TALLOC_CTX *mem_ctx,
						 struct dssetup_DsRoleGetPrimaryDomainInformation *r)
{
	union dssetup_DsRoleInfo *info;

	info = talloc_zero(mem_ctx, union dssetup_DsRoleInfo);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch (r->in.level) {
	case DS_ROLE_BASIC_INFORMATION:
	{
		enum dssetup_DsRole role = DS_ROLE_STANDALONE_SERVER;
		uint32_t flags = 0;
		const char *domain = NULL;
		const char *dns_domain = NULL;
		const char *forest = NULL;
		struct GUID domain_guid;
		struct lsa_policy_state *state;

		NTSTATUS status = dcesrv_lsa_get_policy_state(dce_call, mem_ctx,
							      0, /* we skip access checks */
							      &state);
		if (!NT_STATUS_IS_OK(status)) {
			return ntstatus_to_werror(status);
		}

		ZERO_STRUCT(domain_guid);

		switch (lpcfg_server_role(dce_call->conn->dce_ctx->lp_ctx)) {
		case ROLE_STANDALONE:
			role		= DS_ROLE_STANDALONE_SERVER;
			break;
		case ROLE_DOMAIN_MEMBER:
			role		= DS_ROLE_MEMBER_SERVER;
			break;
		case ROLE_ACTIVE_DIRECTORY_DC:
			if (samdb_is_pdc(state->sam_ldb)) {
				role	= DS_ROLE_PRIMARY_DC;
			} else {
				role    = DS_ROLE_BACKUP_DC;
			}
			break;
		}

		switch (lpcfg_server_role(dce_call->conn->dce_ctx->lp_ctx)) {
		case ROLE_STANDALONE:
			domain		= talloc_strdup(mem_ctx, lpcfg_workgroup(dce_call->conn->dce_ctx->lp_ctx));
			W_ERROR_HAVE_NO_MEMORY(domain);
			break;
		case ROLE_DOMAIN_MEMBER:
			domain		= talloc_strdup(mem_ctx, lpcfg_workgroup(dce_call->conn->dce_ctx->lp_ctx));
			W_ERROR_HAVE_NO_MEMORY(domain);
			/* TODO: what is with dns_domain and forest and guid? */
			break;
		case ROLE_ACTIVE_DIRECTORY_DC:
			flags		= DS_ROLE_PRIMARY_DS_RUNNING;

			if (state->mixed_domain == 1) {
				flags	|= DS_ROLE_PRIMARY_DS_MIXED_MODE;
			}

			domain		= state->domain_name;
			dns_domain	= state->domain_dns;
			forest		= state->forest_dns;

			domain_guid	= state->domain_guid;
			flags	|= DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT;
			break;
		}

		info->basic.role        = role;
		info->basic.flags       = flags;
		info->basic.domain      = domain;
		info->basic.dns_domain  = dns_domain;
		info->basic.forest      = forest;
		info->basic.domain_guid = domain_guid;

		r->out.info = info;
		return WERR_OK;
	}
	case DS_ROLE_UPGRADE_STATUS:
	{
		info->upgrade.upgrading     = DS_ROLE_NOT_UPGRADING;
		info->upgrade.previous_role = DS_ROLE_PREVIOUS_UNKNOWN;

		r->out.info = info;
		return WERR_OK;
	}
	case DS_ROLE_OP_STATUS:
	{
		info->opstatus.status = DS_ROLE_OP_IDLE;

		r->out.info = info;
		return WERR_OK;
	}
	default:
		return WERR_INVALID_PARAM;
	}
}

/*
  fill in the AccountDomain info
*/
static NTSTATUS dcesrv_lsa_info_AccountDomain(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
				       struct lsa_DomainInfo *info)
{
	info->name.string = state->domain_name;
	info->sid         = state->domain_sid;

	return NT_STATUS_OK;
}

/*
  fill in the DNS domain info
*/
static NTSTATUS dcesrv_lsa_info_DNS(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
			     struct lsa_DnsDomainInfo *info)
{
	info->name.string = state->domain_name;
	info->sid         = state->domain_sid;
	info->dns_domain.string = state->domain_dns;
	info->dns_forest.string = state->forest_dns;
	info->domain_guid       = state->domain_guid;

	return NT_STATUS_OK;
}

/*
  lsa_QueryInfoPolicy2
*/
static NTSTATUS dcesrv_lsa_QueryInfoPolicy2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct lsa_QueryInfoPolicy2 *r)
{
	struct lsa_policy_state *state;
	struct dcesrv_handle *h;
	union lsa_PolicyInformation *info;

	*r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	info = talloc_zero(mem_ctx, union lsa_PolicyInformation);
	if (!info) {
		return NT_STATUS_NO_MEMORY;
	}
	*r->out.info = info;

	switch (r->in.level) {
	case LSA_POLICY_INFO_AUDIT_LOG:
		/* we don't need to fill in any of this */
		ZERO_STRUCT(info->audit_log);
		return NT_STATUS_OK;
	case LSA_POLICY_INFO_AUDIT_EVENTS:
		/* we don't need to fill in any of this */
		ZERO_STRUCT(info->audit_events);
		return NT_STATUS_OK;
	case LSA_POLICY_INFO_PD:
		/* we don't need to fill in any of this */
		ZERO_STRUCT(info->pd);
		return NT_STATUS_OK;

	case LSA_POLICY_INFO_DOMAIN:
		return dcesrv_lsa_info_AccountDomain(state, mem_ctx, &info->domain);
	case LSA_POLICY_INFO_ACCOUNT_DOMAIN:
		return dcesrv_lsa_info_AccountDomain(state, mem_ctx, &info->account_domain);
	case LSA_POLICY_INFO_L_ACCOUNT_DOMAIN:
		return dcesrv_lsa_info_AccountDomain(state, mem_ctx, &info->l_account_domain);

	case LSA_POLICY_INFO_ROLE:
		info->role.role = LSA_ROLE_PRIMARY;
		return NT_STATUS_OK;

	case LSA_POLICY_INFO_DNS:
	case LSA_POLICY_INFO_DNS_INT:
		return dcesrv_lsa_info_DNS(state, mem_ctx, &info->dns);

	case LSA_POLICY_INFO_REPLICA:
		ZERO_STRUCT(info->replica);
		return NT_STATUS_OK;

	case LSA_POLICY_INFO_QUOTA:
		ZERO_STRUCT(info->quota);
		return NT_STATUS_OK;

	case LSA_POLICY_INFO_MOD:
	case LSA_POLICY_INFO_AUDIT_FULL_SET:
	case LSA_POLICY_INFO_AUDIT_FULL_QUERY:
		/* windows gives INVALID_PARAMETER */
		*r->out.info = NULL;
		return NT_STATUS_INVALID_PARAMETER;
	}

	*r->out.info = NULL;
	return NT_STATUS_INVALID_INFO_CLASS;
}

/*
  lsa_QueryInfoPolicy
*/
static NTSTATUS dcesrv_lsa_QueryInfoPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct lsa_QueryInfoPolicy *r)
{
	struct lsa_QueryInfoPolicy2 r2;
	NTSTATUS status;

	ZERO_STRUCT(r2);

	r2.in.handle = r->in.handle;
	r2.in.level = r->in.level;
	r2.out.info = r->out.info;

	status = dcesrv_lsa_QueryInfoPolicy2(dce_call, mem_ctx, &r2);

	return status;
}

/*
  lsa_SetInfoPolicy
*/
static NTSTATUS dcesrv_lsa_SetInfoPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_SetInfoPolicy *r)
{
	/* need to support this */
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_ClearAuditLog
*/
static NTSTATUS dcesrv_lsa_ClearAuditLog(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_ClearAuditLog *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


static const struct generic_mapping dcesrv_lsa_account_mapping = {
	LSA_ACCOUNT_READ,
	LSA_ACCOUNT_WRITE,
	LSA_ACCOUNT_EXECUTE,
	LSA_ACCOUNT_ALL_ACCESS
};

/*
  lsa_CreateAccount

  This call does not seem to have any long-term effects, hence no database operations

  we need to talk to the MS product group to find out what this account database means!

  answer is that the lsa database is totally separate from the SAM and
  ldap databases. We are going to need a separate ldb to store these
  accounts. The SIDs on this account bear no relation to the SIDs in
  AD
*/
static NTSTATUS dcesrv_lsa_CreateAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_CreateAccount *r)
{
	struct lsa_account_state *astate;

	struct lsa_policy_state *state;
	struct dcesrv_handle *h, *ah;

	ZERO_STRUCTP(r->out.acct_handle);

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	astate = talloc(dce_call->conn, struct lsa_account_state);
	if (astate == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	astate->account_sid = dom_sid_dup(astate, r->in.sid);
	if (astate->account_sid == NULL) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}

	astate->policy = talloc_reference(astate, state);
	astate->access_mask = r->in.access_mask;

	/*
	 * For now we grant all requested access.
	 *
	 * We will fail at the ldb layer later.
	 */
	if (astate->access_mask & SEC_FLAG_MAXIMUM_ALLOWED) {
		astate->access_mask &= ~SEC_FLAG_MAXIMUM_ALLOWED;
		astate->access_mask |= LSA_ACCOUNT_ALL_ACCESS;
	}
	se_map_generic(&astate->access_mask, &dcesrv_lsa_account_mapping);

	DEBUG(10,("%s: %s access desired[0x%08X] granted[0x%08X].\n",
		  __func__, dom_sid_string(mem_ctx, astate->account_sid),
		 (unsigned)r->in.access_mask,
		 (unsigned)astate->access_mask));

	ah = dcesrv_handle_new(dce_call->context, LSA_HANDLE_ACCOUNT);
	if (!ah) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}

	ah->data = talloc_steal(ah, astate);

	*r->out.acct_handle = ah->wire_handle;

	return NT_STATUS_OK;
}


/*
  lsa_EnumAccounts
*/
static NTSTATUS dcesrv_lsa_EnumAccounts(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_EnumAccounts *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int ret;
	struct ldb_message **res;
	const char * const attrs[] = { "objectSid", NULL};
	uint32_t count, i;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	/* NOTE: This call must only return accounts that have at least
	   one privilege set
	*/
	ret = gendb_search(state->pdb, mem_ctx, NULL, &res, attrs,
			   "(&(objectSid=*)(privilege=*))");
	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (*r->in.resume_handle >= ret) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	count = ret - *r->in.resume_handle;
	if (count > r->in.num_entries) {
		count = r->in.num_entries;
	}

	if (count == 0) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	r->out.sids->sids = talloc_array(r->out.sids, struct lsa_SidPtr, count);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<count;i++) {
		r->out.sids->sids[i].sid =
			samdb_result_dom_sid(r->out.sids->sids,
					     res[i + *r->in.resume_handle],
					     "objectSid");
		NT_STATUS_HAVE_NO_MEMORY(r->out.sids->sids[i].sid);
	}

	r->out.sids->num_sids = count;
	*r->out.resume_handle = count + *r->in.resume_handle;

	return NT_STATUS_OK;
}

/* This decrypts and returns Trusted Domain Auth Information Internal data */
static NTSTATUS get_trustdom_auth_blob(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, DATA_BLOB *auth_blob,
				       struct trustDomainPasswords *auth_struct)
{
	DATA_BLOB session_key = data_blob(NULL, 0);
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	nt_status = dcesrv_fetch_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	arcfour_crypt_blob(auth_blob->data, auth_blob->length, &session_key);
	ndr_err = ndr_pull_struct_blob(auth_blob, mem_ctx,
				       auth_struct,
				       (ndr_pull_flags_fn_t)ndr_pull_trustDomainPasswords);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

static NTSTATUS get_trustauth_inout_blob(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct trustAuthInOutBlob *iopw,
					 DATA_BLOB *trustauth_blob)
{
	enum ndr_err_code ndr_err;

	if (iopw->current.count != iopw->count) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (iopw->previous.count > iopw->current.count) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (iopw->previous.count == 0) {
		/*
		 * If the previous credentials are not present
		 * we need to make a copy.
		 */
		iopw->previous = iopw->current;
	}

	if (iopw->previous.count < iopw->current.count) {
		struct AuthenticationInformationArray *c = &iopw->current;
		struct AuthenticationInformationArray *p = &iopw->previous;

		/*
		 * The previous array needs to have the same size
		 * as the current one.
		 *
		 * We may have to fill with TRUST_AUTH_TYPE_NONE
		 * elements.
		 */
		p->array = talloc_realloc(mem_ctx, p->array,
				   struct AuthenticationInformation,
				   c->count);
		if (p->array == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		while (p->count < c->count) {
			struct AuthenticationInformation *a =
				&p->array[p->count++];

			*a = (struct AuthenticationInformation) {
				.LastUpdateTime = p->array[0].LastUpdateTime,
				.AuthType = TRUST_AUTH_TYPE_NONE,
			};
		}
	}

	ndr_err = ndr_push_struct_blob(trustauth_blob, mem_ctx,
				       iopw,
				       (ndr_push_flags_fn_t)ndr_push_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

static NTSTATUS add_trust_user(TALLOC_CTX *mem_ctx,
			       struct ldb_context *sam_ldb,
			       struct ldb_dn *base_dn,
			       const char *netbios_name,
			       struct trustAuthInOutBlob *in,
			       struct ldb_dn **user_dn)
{
	struct ldb_request *req;
	struct ldb_message *msg;
	struct ldb_dn *dn;
	uint32_t i;
	int ret;

	dn = ldb_dn_copy(mem_ctx, base_dn);
	if (!dn) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!ldb_dn_add_child_fmt(dn, "cn=%s$,cn=users", netbios_name)) {
		return NT_STATUS_NO_MEMORY;
	}

	msg = ldb_msg_new(mem_ctx);
	if (!msg) {
		return NT_STATUS_NO_MEMORY;
	}
	msg->dn = dn;

	ret = ldb_msg_add_string(msg, "objectClass", "user");
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_msg_add_fmt(msg, "samAccountName", "%s$", netbios_name);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_msg_add_uint(sam_ldb, msg, msg, "userAccountControl",
				 UF_INTERDOMAIN_TRUST_ACCOUNT);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < in->count; i++) {
		const char *attribute;
		struct ldb_val v;
		switch (in->current.array[i].AuthType) {
		case TRUST_AUTH_TYPE_NT4OWF:
			attribute = "unicodePwd";
			v.data = (uint8_t *)&in->current.array[i].AuthInfo.nt4owf.password;
			v.length = 16;
			break;
		case TRUST_AUTH_TYPE_CLEAR:
			attribute = "clearTextPassword";
			v.data = in->current.array[i].AuthInfo.clear.password;
			v.length = in->current.array[i].AuthInfo.clear.size;
			break;
		default:
			continue;
		}

		ret = ldb_msg_add_value(msg, attribute, &v, NULL);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* create the trusted_domain user account */
	ret = ldb_build_add_req(&req, sam_ldb, mem_ctx, msg, NULL, NULL,
				ldb_op_default_callback, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_request_add_control(req, DSDB_CONTROL_PERMIT_INTERDOMAIN_TRUST_UAC_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_autotransaction_request(sam_ldb, req);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ldb)));

		switch (ret) {
		case LDB_ERR_ENTRY_ALREADY_EXISTS:
			return NT_STATUS_DOMAIN_EXISTS;
		case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
			return NT_STATUS_ACCESS_DENIED;
		default:
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	if (user_dn) {
		*user_dn = dn;
	}
	return NT_STATUS_OK;
}

/*
  lsa_CreateTrustedDomainEx2
*/
static NTSTATUS dcesrv_lsa_CreateTrustedDomain_base(struct dcesrv_call_state *dce_call,
						    TALLOC_CTX *mem_ctx,
						    struct lsa_CreateTrustedDomainEx2 *r,
						    int op,
						    struct lsa_TrustDomainInfoAuthInfo *unencrypted_auth_info)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_policy_state *policy_state;
	struct lsa_trusted_domain_state *trusted_domain_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs, *msg;
	const char *attrs[] = {
		NULL
	};
	const char *netbios_name;
	const char *dns_name;
	DATA_BLOB trustAuthIncoming, trustAuthOutgoing, auth_blob;
	struct trustDomainPasswords auth_struct;
	int ret;
	NTSTATUS nt_status;
	struct ldb_context *sam_ldb;
	struct server_id *server_ids = NULL;
	uint32_t num_server_ids = 0;
	NTSTATUS status;
	struct dom_sid *tmp_sid1;
	struct dom_sid *tmp_sid2;
	uint32_t tmp_rid;
	bool ok;
	char *dns_encoded = NULL;
	char *netbios_encoded = NULL;
	char *sid_encoded = NULL;

	DCESRV_PULL_HANDLE(policy_handle, r->in.policy_handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.trustdom_handle);

	policy_state = policy_handle->data;
	sam_ldb = policy_state->sam_ldb;

	netbios_name = r->in.info->netbios_name.string;
	if (!netbios_name) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	dns_name = r->in.info->domain_name.string;
	if (dns_name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.info->sid == NULL) {
		return NT_STATUS_INVALID_SID;
	}

	/*
	 * We expect S-1-5-21-A-B-C, but we don't
	 * allow S-1-5-21-0-0-0 as this is used
	 * for claims and compound identities.
	 *
	 * So we call dom_sid_split_rid() 3 times
	 * and compare the result to S-1-5-21
	 */
	status = dom_sid_split_rid(mem_ctx, r->in.info->sid, &tmp_sid1, &tmp_rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = dom_sid_split_rid(mem_ctx, tmp_sid1, &tmp_sid2, &tmp_rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = dom_sid_split_rid(mem_ctx, tmp_sid2, &tmp_sid1, &tmp_rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	ok = dom_sid_parse("S-1-5-21", tmp_sid2);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	ok = dom_sid_equal(tmp_sid1, tmp_sid2);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ok = dom_sid_parse("S-1-5-21-0-0-0", tmp_sid2);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	ok = !dom_sid_equal(r->in.info->sid, tmp_sid2);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	dns_encoded = ldb_binary_encode_string(mem_ctx, dns_name);
	if (dns_encoded == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	netbios_encoded = ldb_binary_encode_string(mem_ctx, netbios_name);
	if (netbios_encoded == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	sid_encoded = ldap_encode_ndr_dom_sid(mem_ctx, r->in.info->sid);
	if (sid_encoded == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	trusted_domain_state = talloc_zero(mem_ctx, struct lsa_trusted_domain_state);
	if (!trusted_domain_state) {
		return NT_STATUS_NO_MEMORY;
	}
	trusted_domain_state->policy = policy_state;

	if (strcasecmp(netbios_name, "BUILTIN") == 0
	    || (strcasecmp(dns_name, "BUILTIN") == 0)
	    || (dom_sid_in_domain(policy_state->builtin_sid, r->in.info->sid))) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strcasecmp(netbios_name, policy_state->domain_name) == 0
	    || strcasecmp(netbios_name, policy_state->domain_dns) == 0
	    || strcasecmp(dns_name, policy_state->domain_dns) == 0
	    || strcasecmp(dns_name, policy_state->domain_name) == 0
	    || (dom_sid_equal(policy_state->domain_sid, r->in.info->sid))) {
		return NT_STATUS_CURRENT_DOMAIN_NOT_ALLOWED;
	}

	/* While this is a REF pointer, some of the functions that wrap this don't provide this */
	if (op == NDR_LSA_CREATETRUSTEDDOMAIN) {
		/* No secrets are created at this time, for this function */
		auth_struct.outgoing.count = 0;
		auth_struct.incoming.count = 0;
	} else if (op == NDR_LSA_CREATETRUSTEDDOMAINEX2) {
		auth_blob = data_blob_const(r->in.auth_info_internal->auth_blob.data,
					    r->in.auth_info_internal->auth_blob.size);
		nt_status = get_trustdom_auth_blob(dce_call, mem_ctx,
						   &auth_blob, &auth_struct);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	} else if (op == NDR_LSA_CREATETRUSTEDDOMAINEX) {

		if (unencrypted_auth_info->incoming_count > 1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* more investigation required here, do not create secrets for
		 * now */
		auth_struct.outgoing.count = 0;
		auth_struct.incoming.count = 0;
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (auth_struct.incoming.count) {
		nt_status = get_trustauth_inout_blob(dce_call, mem_ctx,
						     &auth_struct.incoming,
						     &trustAuthIncoming);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	} else {
		trustAuthIncoming = data_blob(NULL, 0);
	}

	if (auth_struct.outgoing.count) {
		nt_status = get_trustauth_inout_blob(dce_call, mem_ctx,
						     &auth_struct.outgoing,
						     &trustAuthOutgoing);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	} else {
		trustAuthOutgoing = data_blob(NULL, 0);
	}

	ret = ldb_transaction_start(sam_ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* search for the trusted_domain record */
	ret = gendb_search(sam_ldb,
			   mem_ctx, policy_state->system_dn, &msgs, attrs,
			   "(&(objectClass=trustedDomain)(|"
			     "(flatname=%s)(trustPartner=%s)"
			     "(flatname=%s)(trustPartner=%s)"
			     "(securityIdentifier=%s)))",
			   dns_encoded, dns_encoded,
			   netbios_encoded, netbios_encoded,
			   sid_encoded);
	if (ret > 0) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}
	if (ret < 0) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(mem_ctx, policy_state->system_dn);
	if ( ! ldb_dn_add_child_fmt(msg->dn, "cn=%s", dns_name)) {
			ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_msg_add_string(msg, "objectClass", "trustedDomain");
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;;
	}

	ret = ldb_msg_add_string(msg, "flatname", netbios_name);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_msg_add_string(msg, "trustPartner", dns_name);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;;
	}

	ret = samdb_msg_add_dom_sid(sam_ldb, mem_ctx, msg, "securityIdentifier",
				    r->in.info->sid);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;;
	}

	ret = samdb_msg_add_int(sam_ldb, mem_ctx, msg, "trustType", r->in.info->trust_type);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;;
	}

	ret = samdb_msg_add_int(sam_ldb, mem_ctx, msg, "trustAttributes", r->in.info->trust_attributes);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;;
	}

	ret = samdb_msg_add_int(sam_ldb, mem_ctx, msg, "trustDirection", r->in.info->trust_direction);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ldb);
		return NT_STATUS_NO_MEMORY;;
	}

	if (trustAuthIncoming.data) {
		ret = ldb_msg_add_value(msg, "trustAuthIncoming", &trustAuthIncoming, NULL);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(sam_ldb);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (trustAuthOutgoing.data) {
		ret = ldb_msg_add_value(msg, "trustAuthOutgoing", &trustAuthOutgoing, NULL);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(sam_ldb);
			return NT_STATUS_NO_MEMORY;
		}
	}

	trusted_domain_state->trusted_domain_dn = talloc_reference(trusted_domain_state, msg->dn);

	/* create the trusted_domain */
	ret = ldb_add(sam_ldb, msg);
	switch (ret) {
	case  LDB_SUCCESS:
		break;
	case  LDB_ERR_ENTRY_ALREADY_EXISTS:
		ldb_transaction_cancel(sam_ldb);
		DEBUG(0,("Failed to create trusted domain record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ldb)));
		return NT_STATUS_DOMAIN_EXISTS;
	case  LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		ldb_transaction_cancel(sam_ldb);
		DEBUG(0,("Failed to create trusted domain record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ldb)));
		return NT_STATUS_ACCESS_DENIED;
	default:
		ldb_transaction_cancel(sam_ldb);
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ldb)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (r->in.info->trust_direction & LSA_TRUST_DIRECTION_INBOUND) {
		struct ldb_dn *user_dn;
		/* Inbound trusts must also create a cn=users object to match */
		nt_status = add_trust_user(mem_ctx, sam_ldb,
					   policy_state->domain_dn,
					   netbios_name,
					   &auth_struct.incoming,
					   &user_dn);
		if (!NT_STATUS_IS_OK(nt_status)) {
			ldb_transaction_cancel(sam_ldb);
			return nt_status;
		}

		/* save the trust user dn */
		trusted_domain_state->trusted_domain_user_dn
			= talloc_steal(trusted_domain_state, user_dn);
	}

	ret = ldb_transaction_commit(sam_ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/*
	 * Notify winbindd that we have a new trust
	 */
	status = irpc_servers_byname(dce_call->msg_ctx,
				     mem_ctx,
				     "winbind_server",
				     &num_server_ids, &server_ids);
	if (NT_STATUS_IS_OK(status) && num_server_ids >= 1) {
		enum ndr_err_code ndr_err;
		DATA_BLOB b = {};

		ndr_err = ndr_push_struct_blob(&b, mem_ctx, r->in.info,
			(ndr_push_flags_fn_t)ndr_push_lsa_TrustDomainInfoInfoEx);
		if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			imessaging_send(dce_call->msg_ctx, server_ids[0],
				MSG_WINBIND_NEW_TRUSTED_DOMAIN, &b);
		}
	}
	TALLOC_FREE(server_ids);

	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_TRUSTED_DOMAIN);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = talloc_steal(handle, trusted_domain_state);

	trusted_domain_state->access_mask = r->in.access_mask;
	trusted_domain_state->policy = talloc_reference(trusted_domain_state, policy_state);

	*r->out.trustdom_handle = handle->wire_handle;

	return NT_STATUS_OK;
}

/*
  lsa_CreateTrustedDomainEx2
*/
static NTSTATUS dcesrv_lsa_CreateTrustedDomainEx2(struct dcesrv_call_state *dce_call,
					   TALLOC_CTX *mem_ctx,
					   struct lsa_CreateTrustedDomainEx2 *r)
{
	return dcesrv_lsa_CreateTrustedDomain_base(dce_call, mem_ctx, r, NDR_LSA_CREATETRUSTEDDOMAINEX2, NULL);
}
/*
  lsa_CreateTrustedDomainEx
*/
static NTSTATUS dcesrv_lsa_CreateTrustedDomainEx(struct dcesrv_call_state *dce_call,
					  TALLOC_CTX *mem_ctx,
					  struct lsa_CreateTrustedDomainEx *r)
{
	struct lsa_CreateTrustedDomainEx2 r2;

	r2.in.policy_handle = r->in.policy_handle;
	r2.in.info = r->in.info;
	r2.out.trustdom_handle = r->out.trustdom_handle;
	return dcesrv_lsa_CreateTrustedDomain_base(dce_call, mem_ctx, &r2, NDR_LSA_CREATETRUSTEDDOMAINEX, r->in.auth_info);
}

/*
  lsa_CreateTrustedDomain
*/
static NTSTATUS dcesrv_lsa_CreateTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct lsa_CreateTrustedDomain *r)
{
	struct lsa_CreateTrustedDomainEx2 r2;

	r2.in.policy_handle = r->in.policy_handle;
	r2.in.info = talloc(mem_ctx, struct lsa_TrustDomainInfoInfoEx);
	if (!r2.in.info) {
		return NT_STATUS_NO_MEMORY;
	}

	r2.in.info->domain_name = r->in.info->name;
	r2.in.info->netbios_name = r->in.info->name;
	r2.in.info->sid = r->in.info->sid;
	r2.in.info->trust_direction = LSA_TRUST_DIRECTION_OUTBOUND;
	r2.in.info->trust_type = LSA_TRUST_TYPE_DOWNLEVEL;
	r2.in.info->trust_attributes = 0;

	r2.in.access_mask = r->in.access_mask;
	r2.out.trustdom_handle = r->out.trustdom_handle;

	return dcesrv_lsa_CreateTrustedDomain_base(dce_call, mem_ctx, &r2, NDR_LSA_CREATETRUSTEDDOMAIN, NULL);
}

static NTSTATUS dcesrv_lsa_OpenTrustedDomain_common(
					struct dcesrv_call_state *dce_call,
					TALLOC_CTX *tmp_mem,
					struct lsa_policy_state *policy_state,
					const char *filter,
					uint32_t access_mask,
					struct dcesrv_handle **_handle)
{
	struct lsa_trusted_domain_state *trusted_domain_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs;
	const char *attrs[] = {
		"trustDirection",
		"flatname",
		NULL
	};
	uint32_t direction;
	int ret;

        /* TODO: perform access checks */

	/* search for the trusted_domain record */
	ret = gendb_search(policy_state->sam_ldb, tmp_mem,
			   policy_state->system_dn,
			   &msgs, attrs, "%s", filter);
	if (ret == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (ret != 1) {
		DEBUG(0,("Found %d records matching %s under %s\n", ret,
			 filter,
			 ldb_dn_get_linearized(policy_state->system_dn)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	trusted_domain_state = talloc_zero(tmp_mem,
					   struct lsa_trusted_domain_state);
	if (!trusted_domain_state) {
		return NT_STATUS_NO_MEMORY;
	}
	trusted_domain_state->policy = policy_state;

	trusted_domain_state->trusted_domain_dn =
		talloc_steal(trusted_domain_state, msgs[0]->dn);

	direction = ldb_msg_find_attr_as_int(msgs[0], "trustDirection", 0);
	if (direction & LSA_TRUST_DIRECTION_INBOUND) {
		const char *flatname = ldb_msg_find_attr_as_string(msgs[0],
							"flatname", NULL);

		/* search for the trusted_domain account */
		ret = gendb_search(policy_state->sam_ldb, tmp_mem,
				   policy_state->domain_dn,
				   &msgs, attrs,
				   "(&(samaccountname=%s$)(objectclass=user)"
				   "(userAccountControl:%s:=%u))",
				   flatname,
				   LDB_OID_COMPARATOR_AND,
				   UF_INTERDOMAIN_TRUST_ACCOUNT);
		if (ret == 1) {
			trusted_domain_state->trusted_domain_user_dn =
				talloc_steal(trusted_domain_state, msgs[0]->dn);
		}
	}

	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_TRUSTED_DOMAIN);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = talloc_steal(handle, trusted_domain_state);

	trusted_domain_state->access_mask = access_mask;
	trusted_domain_state->policy = talloc_reference(trusted_domain_state,
							policy_state);

	*_handle = handle;

	return NT_STATUS_OK;
}

/*
  lsa_OpenTrustedDomain
*/
static NTSTATUS dcesrv_lsa_OpenTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct lsa_OpenTrustedDomain *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_policy_state *policy_state;
	struct dcesrv_handle *handle;
	const char *sid_string;
	char *filter;
	NTSTATUS status;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.trustdom_handle);
	policy_state = policy_handle->data;

	sid_string = dom_sid_string(mem_ctx, r->in.sid);
	if (!sid_string) {
		return NT_STATUS_NO_MEMORY;
	}

	filter = talloc_asprintf(mem_ctx,
				 "(&(securityIdentifier=%s)"
				 "(objectclass=trustedDomain))",
				 sid_string);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcesrv_lsa_OpenTrustedDomain_common(dce_call, mem_ctx,
						     policy_state,
						     filter,
						     r->in.access_mask,
						     &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*r->out.trustdom_handle = handle->wire_handle;

	return NT_STATUS_OK;
}


/*
  lsa_OpenTrustedDomainByName
*/
static NTSTATUS dcesrv_lsa_OpenTrustedDomainByName(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct lsa_OpenTrustedDomainByName *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_policy_state *policy_state;
	struct dcesrv_handle *handle;
	char *td_name;
	char *filter;
	NTSTATUS status;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.trustdom_handle);
	policy_state = policy_handle->data;

	if (!r->in.name.string) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* search for the trusted_domain record */
	td_name = ldb_binary_encode_string(mem_ctx, r->in.name.string);
	if (td_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	filter = talloc_asprintf(mem_ctx,
			   "(&(|(flatname=%s)(cn=%s)(trustPartner=%s))"
			     "(objectclass=trustedDomain))",
			   td_name, td_name, td_name);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcesrv_lsa_OpenTrustedDomain_common(dce_call, mem_ctx,
						     policy_state,
						     filter,
						     r->in.access_mask,
						     &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*r->out.trustdom_handle = handle->wire_handle;

	return NT_STATUS_OK;
}



/*
  lsa_SetTrustedDomainInfo
*/
static NTSTATUS dcesrv_lsa_SetTrustedDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct lsa_SetTrustedDomainInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/* parameters 4 to 6 are optional if the dn is a dn of a TDO object,
 * otherwise at least one must be provided */
static NTSTATUS get_tdo(struct ldb_context *sam, TALLOC_CTX *mem_ctx,
			struct ldb_dn *basedn, const char *dns_domain,
			const char *netbios, struct dom_sid2 *sid,
			struct ldb_message ***msgs)
{
	const char *attrs[] = { "flatname", "trustPartner",
				"securityIdentifier", "trustDirection",
				"trustType", "trustAttributes",
				"trustPosixOffset",
				"msDs-supportedEncryptionTypes",
				"msDS-TrustForestTrustInfo",
				NULL
	};
	char *dns = NULL;
	char *nbn = NULL;
	char *sidstr = NULL;
	char *filter;
	int ret;


	if (dns_domain || netbios || sid) {
		filter = talloc_strdup(mem_ctx,
				   "(&(objectclass=trustedDomain)(|");
	} else {
		filter = talloc_strdup(mem_ctx,
				       "(objectclass=trustedDomain)");
	}
	if (!filter) {
		return NT_STATUS_NO_MEMORY;
	}

	if (dns_domain) {
		dns = ldb_binary_encode_string(mem_ctx, dns_domain);
		if (!dns) {
			return NT_STATUS_NO_MEMORY;
		}
		filter = talloc_asprintf_append(filter,
						"(trustPartner=%s)", dns);
		if (!filter) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (netbios) {
		nbn = ldb_binary_encode_string(mem_ctx, netbios);
		if (!nbn) {
			return NT_STATUS_NO_MEMORY;
		}
		filter = talloc_asprintf_append(filter,
						"(flatname=%s)", nbn);
		if (!filter) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (sid) {
		sidstr = dom_sid_string(mem_ctx, sid);
		if (!sidstr) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		filter = talloc_asprintf_append(filter,
						"(securityIdentifier=%s)",
						sidstr);
		if (!filter) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (dns_domain || netbios || sid) {
		filter = talloc_asprintf_append(filter, "))");
		if (!filter) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	ret = gendb_search(sam, mem_ctx, basedn, msgs, attrs, "%s", filter);
	if (ret == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (ret != 1) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	return NT_STATUS_OK;
}

static NTSTATUS update_uint32_t_value(TALLOC_CTX *mem_ctx,
				      struct ldb_context *sam_ldb,
				      struct ldb_message *orig,
				      struct ldb_message *dest,
				      const char *attribute,
				      uint32_t value,
				      uint32_t *orig_value)
{
	const struct ldb_val *orig_val;
	uint32_t orig_uint = 0;
	unsigned int flags = 0;
	int ret;

	orig_val = ldb_msg_find_ldb_val(orig, attribute);
	if (!orig_val || !orig_val->data) {
		/* add new attribute */
		flags = LDB_FLAG_MOD_ADD;

	} else {
		errno = 0;
		orig_uint = strtoul((const char *)orig_val->data, NULL, 0);
		if (errno != 0 || orig_uint != value) {
			/* replace also if can't get value */
			flags = LDB_FLAG_MOD_REPLACE;
		}
	}

	if (flags == 0) {
		/* stored value is identical, nothing to change */
		goto done;
	}

	ret = ldb_msg_add_empty(dest, attribute, flags, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_msg_add_uint(sam_ldb, dest, dest, attribute, value);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

done:
	if (orig_value) {
		*orig_value = orig_uint;
	}
	return NT_STATUS_OK;
}

static NTSTATUS update_trust_user(TALLOC_CTX *mem_ctx,
				  struct ldb_context *sam_ldb,
				  struct ldb_dn *base_dn,
				  bool delete_user,
				  const char *netbios_name,
				  struct trustAuthInOutBlob *in)
{
	const char *attrs[] = { "userAccountControl", NULL };
	struct ldb_message **msgs;
	struct ldb_message *msg;
	uint32_t uac;
	uint32_t i;
	int ret;

	ret = gendb_search(sam_ldb, mem_ctx,
			   base_dn, &msgs, attrs,
			   "samAccountName=%s$", netbios_name);
	if (ret > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (ret == 0) {
		if (delete_user) {
			return NT_STATUS_OK;
		}

		/* ok no existing user, add it from scratch */
		return add_trust_user(mem_ctx, sam_ldb, base_dn,
				      netbios_name, in, NULL);
	}

	/* check user is what we are looking for */
	uac = ldb_msg_find_attr_as_uint(msgs[0],
					"userAccountControl", 0);
	if (!(uac & UF_INTERDOMAIN_TRUST_ACCOUNT)) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	if (delete_user) {
		ret = ldb_delete(sam_ldb, msgs[0]->dn);
		switch (ret) {
		case LDB_SUCCESS:
			return NT_STATUS_OK;
		case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
			return NT_STATUS_ACCESS_DENIED;
		default:
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	/* entry exists, just modify secret if any */
	if (in == NULL || in->count == 0) {
		return NT_STATUS_OK;
	}

	msg = ldb_msg_new(mem_ctx);
	if (!msg) {
		return NT_STATUS_NO_MEMORY;
	}
	msg->dn = msgs[0]->dn;

	for (i = 0; i < in->count; i++) {
		const char *attribute;
		struct ldb_val v;
		switch (in->current.array[i].AuthType) {
		case TRUST_AUTH_TYPE_NT4OWF:
			attribute = "unicodePwd";
			v.data = (uint8_t *)&in->current.array[i].AuthInfo.nt4owf.password;
			v.length = 16;
			break;
		case TRUST_AUTH_TYPE_CLEAR:
			attribute = "clearTextPassword";
			v.data = in->current.array[i].AuthInfo.clear.password;
			v.length = in->current.array[i].AuthInfo.clear.size;
			break;
		default:
			continue;
		}

		ret = ldb_msg_add_empty(msg, attribute,
					LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}

		ret = ldb_msg_add_value(msg, attribute, &v, NULL);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* create the trusted_domain user account */
	ret = ldb_modify(sam_ldb, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ldb)));

		switch (ret) {
		case LDB_ERR_ENTRY_ALREADY_EXISTS:
			return NT_STATUS_DOMAIN_EXISTS;
		case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
			return NT_STATUS_ACCESS_DENIED;
		default:
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	return NT_STATUS_OK;
}


static NTSTATUS setInfoTrustedDomain_base(struct dcesrv_call_state *dce_call,
					  struct lsa_policy_state *p_state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message *dom_msg,
					  enum lsa_TrustDomInfoEnum level,
					  union lsa_TrustedDomainInfo *info)
{
	uint32_t *posix_offset = NULL;
	struct lsa_TrustDomainInfoInfoEx *info_ex = NULL;
	struct lsa_TrustDomainInfoAuthInfo *auth_info = NULL;
	struct lsa_TrustDomainInfoAuthInfoInternal *auth_info_int = NULL;
	uint32_t *enc_types = NULL;
	DATA_BLOB trustAuthIncoming, trustAuthOutgoing, auth_blob;
	struct trustDomainPasswords auth_struct;
	struct trustAuthInOutBlob *current_passwords = NULL;
	NTSTATUS nt_status;
	struct ldb_message **msgs;
	struct ldb_message *msg;
	bool add_outgoing = false;
	bool add_incoming = false;
	bool del_outgoing = false;
	bool del_incoming = false;
	bool del_forest_info = false;
	bool in_transaction = false;
	int ret;
	bool am_rodc;

	switch (level) {
	case LSA_TRUSTED_DOMAIN_INFO_POSIX_OFFSET:
		posix_offset = &info->posix_offset.posix_offset;
		break;
	case LSA_TRUSTED_DOMAIN_INFO_INFO_EX:
		info_ex = &info->info_ex;
		break;
	case LSA_TRUSTED_DOMAIN_INFO_AUTH_INFO:
		auth_info = &info->auth_info;
		break;
	case LSA_TRUSTED_DOMAIN_INFO_FULL_INFO:
		posix_offset = &info->full_info.posix_offset.posix_offset;
		info_ex = &info->full_info.info_ex;
		auth_info = &info->full_info.auth_info;
		break;
	case LSA_TRUSTED_DOMAIN_INFO_AUTH_INFO_INTERNAL:
		auth_info_int = &info->auth_info_internal;
		break;
	case LSA_TRUSTED_DOMAIN_INFO_FULL_INFO_INTERNAL:
		posix_offset = &info->full_info_internal.posix_offset.posix_offset;
		info_ex = &info->full_info_internal.info_ex;
		auth_info_int = &info->full_info_internal.auth_info;
		break;
	case LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES:
		enc_types = &info->enc_types.enc_types;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (auth_info) {
		nt_status = auth_info_2_auth_blob(mem_ctx, auth_info,
						  &trustAuthIncoming,
						  &trustAuthOutgoing);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		if (trustAuthIncoming.data) {
			/* This does the decode of some of this twice, but it is easier that way */
			nt_status = auth_info_2_trustauth_inout(mem_ctx,
								auth_info->incoming_count,
								auth_info->incoming_current_auth_info,
								NULL,
								&current_passwords);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}
		}
	}

	/* decode auth_info_int if set */
	if (auth_info_int) {

		/* now decrypt blob */
		auth_blob = data_blob_const(auth_info_int->auth_blob.data,
					    auth_info_int->auth_blob.size);

		nt_status = get_trustdom_auth_blob(dce_call, mem_ctx,
						   &auth_blob, &auth_struct);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}

	if (info_ex) {
		/* verify data matches */
		if (info_ex->trust_attributes &
		    LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			/* TODO: check what behavior level we have */
		       if (strcasecmp_m(p_state->domain_dns,
					p_state->forest_dns) != 0) {
				return NT_STATUS_INVALID_DOMAIN_STATE;
			}
		}

		ret = samdb_rodc(p_state->sam_ldb, &am_rodc);
		if (ret == LDB_SUCCESS && am_rodc) {
			return NT_STATUS_NO_SUCH_DOMAIN;
		}

		/* verify only one object matches the dns/netbios/sid
		 * triplet and that this is the one we already have */
		nt_status = get_tdo(p_state->sam_ldb, mem_ctx,
				    p_state->system_dn,
				    info_ex->domain_name.string,
				    info_ex->netbios_name.string,
				    info_ex->sid, &msgs);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		if (ldb_dn_compare(dom_msg->dn, msgs[0]->dn) != 0) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
		talloc_free(msgs);
	}

	/* TODO: should we fetch previous values from the existing entry
	 * and append them ? */
	if (auth_info_int && auth_struct.incoming.count) {
		nt_status = get_trustauth_inout_blob(dce_call, mem_ctx,
						     &auth_struct.incoming,
						     &trustAuthIncoming);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		current_passwords = &auth_struct.incoming;

	} else {
		trustAuthIncoming = data_blob(NULL, 0);
	}

	if (auth_info_int && auth_struct.outgoing.count) {
		nt_status = get_trustauth_inout_blob(dce_call, mem_ctx,
						     &auth_struct.outgoing,
						     &trustAuthOutgoing);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	} else {
		trustAuthOutgoing = data_blob(NULL, 0);
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	msg->dn = dom_msg->dn;

	if (posix_offset) {
		nt_status = update_uint32_t_value(mem_ctx, p_state->sam_ldb,
						  dom_msg, msg,
						  "trustPosixOffset",
						  *posix_offset, NULL);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}

	if (info_ex) {
		uint32_t origattrs;
		uint32_t changed_attrs;
		uint32_t origdir;
		int origtype;

		nt_status = update_uint32_t_value(mem_ctx, p_state->sam_ldb,
						  dom_msg, msg,
						  "trustDirection",
						  info_ex->trust_direction,
						  &origdir);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		if (info_ex->trust_direction & LSA_TRUST_DIRECTION_INBOUND) {
			if (auth_info != NULL && trustAuthIncoming.length > 0) {
				add_incoming = true;
			}
		}
		if (info_ex->trust_direction & LSA_TRUST_DIRECTION_OUTBOUND) {
			if (auth_info != NULL && trustAuthOutgoing.length > 0) {
				add_outgoing = true;
			}
		}

		if ((origdir & LSA_TRUST_DIRECTION_INBOUND) &&
		    !(info_ex->trust_direction & LSA_TRUST_DIRECTION_INBOUND)) {
			del_incoming = true;
		}
		if ((origdir & LSA_TRUST_DIRECTION_OUTBOUND) &&
		    !(info_ex->trust_direction & LSA_TRUST_DIRECTION_OUTBOUND)) {
			del_outgoing = true;
		}

		origtype = ldb_msg_find_attr_as_int(dom_msg, "trustType", -1);
		if (origtype == -1 || origtype != info_ex->trust_type) {
			DEBUG(1, ("Attempted to change trust type! "
				  "Operation not handled\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}

		nt_status = update_uint32_t_value(mem_ctx, p_state->sam_ldb,
						  dom_msg, msg,
						  "trustAttributes",
						  info_ex->trust_attributes,
						  &origattrs);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		/* TODO: check forestFunctionality from ldb opaque */
		/* TODO: check what is set makes sense */

		changed_attrs = origattrs ^ info_ex->trust_attributes;
		if (changed_attrs & ~LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			/*
			 * For now we only allow
			 * LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE to be changed.
			 *
			 * TODO: we may need to support more attribute changes
			 */
			DEBUG(1, ("Attempted to change trust attributes "
				  "(0x%08x != 0x%08x)! "
				  "Operation not handled yet...\n",
				  (unsigned)origattrs,
				  (unsigned)info_ex->trust_attributes));
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!(info_ex->trust_attributes &
		      LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE))
		{
			struct ldb_message_element *orig_forest_el = NULL;

			orig_forest_el = ldb_msg_find_element(dom_msg,
						"msDS-TrustForestTrustInfo");
			if (orig_forest_el != NULL) {
				del_forest_info = true;
			}
		}
	}

	if (enc_types) {
		nt_status = update_uint32_t_value(mem_ctx, p_state->sam_ldb,
						  dom_msg, msg,
						  "msDS-SupportedEncryptionTypes",
						  *enc_types, NULL);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}

	if (add_incoming || del_incoming) {
		ret = ldb_msg_add_empty(msg, "trustAuthIncoming",
					LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
		if (add_incoming) {
			ret = ldb_msg_add_value(msg, "trustAuthIncoming",
						&trustAuthIncoming, NULL);
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		}
	}
	if (add_outgoing || del_outgoing) {
		ret = ldb_msg_add_empty(msg, "trustAuthOutgoing",
					LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
		if (add_outgoing) {
			ret = ldb_msg_add_value(msg, "trustAuthOutgoing",
						&trustAuthOutgoing, NULL);
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		}
	}
	if (del_forest_info) {
		ret = ldb_msg_add_empty(msg, "msDS-TrustForestTrustInfo",
					LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* start transaction */
	ret = ldb_transaction_start(p_state->sam_ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	in_transaction = true;

	if (msg->num_elements) {
		ret = ldb_modify(p_state->sam_ldb, msg);
		if (ret != LDB_SUCCESS) {
			DEBUG(1,("Failed to modify trusted domain record %s: %s\n",
				 ldb_dn_get_linearized(msg->dn),
				 ldb_errstring(p_state->sam_ldb)));
			nt_status = dsdb_ldb_err_to_ntstatus(ret);
			goto done;
		}
	}

	if (add_incoming || del_incoming) {
		const char *netbios_name;

		netbios_name = ldb_msg_find_attr_as_string(dom_msg,
							   "flatname", NULL);
		if (!netbios_name) {
			nt_status = NT_STATUS_INVALID_DOMAIN_STATE;
			goto done;
		}

		/* We use trustAuthIncoming.data to incidate that auth_struct.incoming is valid */
		nt_status = update_trust_user(mem_ctx,
					      p_state->sam_ldb,
					      p_state->domain_dn,
					      del_incoming,
					      netbios_name,
					      current_passwords);
		if (!NT_STATUS_IS_OK(nt_status)) {
			goto done;
		}
	}

	/* ok, all fine, commit transaction and return */
	ret = ldb_transaction_commit(p_state->sam_ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	in_transaction = false;

	nt_status = NT_STATUS_OK;

done:
	if (in_transaction) {
		ldb_transaction_cancel(p_state->sam_ldb);
	}
	return nt_status;
}

/*
  lsa_SetInfomrationTrustedDomain
*/
static NTSTATUS dcesrv_lsa_SetInformationTrustedDomain(
				struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct lsa_SetInformationTrustedDomain *r)
{
	struct dcesrv_handle *h;
	struct lsa_trusted_domain_state *td_state;
	struct ldb_message **msgs;
	NTSTATUS nt_status;

	DCESRV_PULL_HANDLE(h, r->in.trustdom_handle,
			   LSA_HANDLE_TRUSTED_DOMAIN);

	td_state = talloc_get_type(h->data, struct lsa_trusted_domain_state);

	/* get the trusted domain object */
	nt_status = get_tdo(td_state->policy->sam_ldb, mem_ctx,
			    td_state->trusted_domain_dn,
			    NULL, NULL, NULL, &msgs);
	if (!NT_STATUS_IS_OK(nt_status)) {
		if (NT_STATUS_EQUAL(nt_status,
				    NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			return nt_status;
		}
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return setInfoTrustedDomain_base(dce_call, td_state->policy, mem_ctx,
					 msgs[0], r->in.level, r->in.info);
}


/*
  lsa_DeleteTrustedDomain
*/
static NTSTATUS dcesrv_lsa_DeleteTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct lsa_DeleteTrustedDomain *r)
{
	NTSTATUS status;
	struct lsa_OpenTrustedDomain opn = {{0},{0}};
	struct lsa_DeleteObject del;
	struct dcesrv_handle *h;

	opn.in.handle = r->in.handle;
	opn.in.sid = r->in.dom_sid;
	opn.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	opn.out.trustdom_handle = talloc(mem_ctx, struct policy_handle);
	if (!opn.out.trustdom_handle) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_lsa_OpenTrustedDomain(dce_call, mem_ctx, &opn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DCESRV_PULL_HANDLE(h, opn.out.trustdom_handle, DCESRV_HANDLE_ANY);
	talloc_steal(mem_ctx, h);

	del.in.handle = opn.out.trustdom_handle;
	del.out.handle = opn.out.trustdom_handle;
	status = dcesrv_lsa_DeleteObject(dce_call, mem_ctx, &del);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return NT_STATUS_OK;
}

static NTSTATUS fill_trust_domain_ex(TALLOC_CTX *mem_ctx,
				     struct ldb_message *msg,
				     struct lsa_TrustDomainInfoInfoEx *info_ex)
{
	info_ex->domain_name.string
		= ldb_msg_find_attr_as_string(msg, "trustPartner", NULL);
	info_ex->netbios_name.string
		= ldb_msg_find_attr_as_string(msg, "flatname", NULL);
	info_ex->sid
		= samdb_result_dom_sid(mem_ctx, msg, "securityIdentifier");
	info_ex->trust_direction
		= ldb_msg_find_attr_as_int(msg, "trustDirection", 0);
	info_ex->trust_type
		= ldb_msg_find_attr_as_int(msg, "trustType", 0);
	info_ex->trust_attributes
		= ldb_msg_find_attr_as_int(msg, "trustAttributes", 0);
	return NT_STATUS_OK;
}

/*
  lsa_QueryTrustedDomainInfo
*/
static NTSTATUS dcesrv_lsa_QueryTrustedDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					   struct lsa_QueryTrustedDomainInfo *r)
{
	union lsa_TrustedDomainInfo *info = NULL;
	struct dcesrv_handle *h;
	struct lsa_trusted_domain_state *trusted_domain_state;
	struct ldb_message *msg;
	int ret;
	struct ldb_message **res;
	const char *attrs[] = {
		"flatname",
		"trustPartner",
		"securityIdentifier",
		"trustDirection",
		"trustType",
		"trustAttributes",
		"msDs-supportedEncryptionTypes",
		NULL
	};

	DCESRV_PULL_HANDLE(h, r->in.trustdom_handle, LSA_HANDLE_TRUSTED_DOMAIN);

	trusted_domain_state = talloc_get_type(h->data, struct lsa_trusted_domain_state);

	/* pull all the user attributes */
	ret = gendb_search_dn(trusted_domain_state->policy->sam_ldb, mem_ctx,
			      trusted_domain_state->trusted_domain_dn, &res, attrs);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	info = talloc_zero(mem_ctx, union lsa_TrustedDomainInfo);
	if (!info) {
		return NT_STATUS_NO_MEMORY;
	}
	*r->out.info = info;

	switch (r->in.level) {
	case LSA_TRUSTED_DOMAIN_INFO_NAME:
		info->name.netbios_name.string
			= ldb_msg_find_attr_as_string(msg, "flatname", NULL);
		break;
	case LSA_TRUSTED_DOMAIN_INFO_POSIX_OFFSET:
		info->posix_offset.posix_offset
			= ldb_msg_find_attr_as_uint(msg, "posixOffset", 0);
		break;
#if 0  /* Win2k3 doesn't implement this */
	case LSA_TRUSTED_DOMAIN_INFO_BASIC:
		r->out.info->info_basic.netbios_name.string
			= ldb_msg_find_attr_as_string(msg, "flatname", NULL);
		r->out.info->info_basic.sid
			= samdb_result_dom_sid(mem_ctx, msg, "securityIdentifier");
		break;
#endif
	case LSA_TRUSTED_DOMAIN_INFO_INFO_EX:
		return fill_trust_domain_ex(mem_ctx, msg, &info->info_ex);

	case LSA_TRUSTED_DOMAIN_INFO_FULL_INFO:
		ZERO_STRUCT(info->full_info);
		return fill_trust_domain_ex(mem_ctx, msg, &info->full_info.info_ex);
	case LSA_TRUSTED_DOMAIN_INFO_FULL_INFO_2_INTERNAL:
		ZERO_STRUCT(info->full_info2_internal);
		info->full_info2_internal.posix_offset.posix_offset
			= ldb_msg_find_attr_as_uint(msg, "posixOffset", 0);
		return fill_trust_domain_ex(mem_ctx, msg, &info->full_info2_internal.info.info_ex);

	case LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES:
		info->enc_types.enc_types
			= ldb_msg_find_attr_as_uint(msg, "msDs-supportedEncryptionTypes", KERB_ENCTYPE_RC4_HMAC_MD5);
		break;

	case LSA_TRUSTED_DOMAIN_INFO_CONTROLLERS:
	case LSA_TRUSTED_DOMAIN_INFO_INFO_EX2_INTERNAL:
		/* oops, we don't want to return the info after all */
		talloc_free(info);
		*r->out.info = NULL;
		return NT_STATUS_INVALID_PARAMETER;
	default:
		/* oops, we don't want to return the info after all */
		talloc_free(info);
		*r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	return NT_STATUS_OK;
}


/*
  lsa_QueryTrustedDomainInfoBySid
*/
static NTSTATUS dcesrv_lsa_QueryTrustedDomainInfoBySid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct lsa_QueryTrustedDomainInfoBySid *r)
{
	NTSTATUS status;
	struct lsa_OpenTrustedDomain opn = {{0},{0}};
	struct lsa_QueryTrustedDomainInfo query;
	struct dcesrv_handle *h;

	opn.in.handle = r->in.handle;
	opn.in.sid = r->in.dom_sid;
	opn.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	opn.out.trustdom_handle = talloc(mem_ctx, struct policy_handle);
	if (!opn.out.trustdom_handle) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_lsa_OpenTrustedDomain(dce_call, mem_ctx, &opn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ensure this handle goes away at the end of this call */
	DCESRV_PULL_HANDLE(h, opn.out.trustdom_handle, DCESRV_HANDLE_ANY);
	talloc_steal(mem_ctx, h);

	query.in.trustdom_handle = opn.out.trustdom_handle;
	query.in.level = r->in.level;
	query.out.info = r->out.info;
	status = dcesrv_lsa_QueryTrustedDomainInfo(dce_call, mem_ctx, &query);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/*
  lsa_SetTrustedDomainInfoByName
*/
static NTSTATUS dcesrv_lsa_SetTrustedDomainInfoByName(struct dcesrv_call_state *dce_call,
					       TALLOC_CTX *mem_ctx,
					       struct lsa_SetTrustedDomainInfoByName *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_policy_state *policy_state;
	struct ldb_message **msgs;
	NTSTATUS nt_status;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	policy_state = policy_handle->data;

	/* get the trusted domain object */
	nt_status = get_tdo(policy_state->sam_ldb, mem_ctx,
			    policy_state->domain_dn,
			    r->in.trusted_domain->string,
			    r->in.trusted_domain->string,
			    NULL, &msgs);
	if (!NT_STATUS_IS_OK(nt_status)) {
		if (NT_STATUS_EQUAL(nt_status,
				    NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			return nt_status;
		}
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return setInfoTrustedDomain_base(dce_call, policy_state, mem_ctx,
					 msgs[0], r->in.level, r->in.info);
}

/*
   lsa_QueryTrustedDomainInfoByName
*/
static NTSTATUS dcesrv_lsa_QueryTrustedDomainInfoByName(struct dcesrv_call_state *dce_call,
						 TALLOC_CTX *mem_ctx,
						 struct lsa_QueryTrustedDomainInfoByName *r)
{
	NTSTATUS status;
	struct lsa_OpenTrustedDomainByName opn = {{0},{0}};
	struct lsa_QueryTrustedDomainInfo query;
	struct dcesrv_handle *h;

	opn.in.handle = r->in.handle;
	opn.in.name = *r->in.trusted_domain;
	opn.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	opn.out.trustdom_handle = talloc(mem_ctx, struct policy_handle);
	if (!opn.out.trustdom_handle) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_lsa_OpenTrustedDomainByName(dce_call, mem_ctx, &opn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ensure this handle goes away at the end of this call */
	DCESRV_PULL_HANDLE(h, opn.out.trustdom_handle, DCESRV_HANDLE_ANY);
	talloc_steal(mem_ctx, h);

	query.in.trustdom_handle = opn.out.trustdom_handle;
	query.in.level = r->in.level;
	query.out.info = r->out.info;
	status = dcesrv_lsa_QueryTrustedDomainInfo(dce_call, mem_ctx, &query);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/*
  lsa_CloseTrustedDomainEx
*/
static NTSTATUS dcesrv_lsa_CloseTrustedDomainEx(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct lsa_CloseTrustedDomainEx *r)
{
	/* The result of a bad hair day from an IDL programmer?  Not
	 * implmented in Win2k3.  You should always just lsa_Close
	 * anyway. */
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  comparison function for sorting lsa_DomainInformation array
*/
static int compare_DomainInfo(struct lsa_DomainInfo *e1, struct lsa_DomainInfo *e2)
{
	return strcasecmp_m(e1->name.string, e2->name.string);
}

/*
  lsa_EnumTrustDom
*/
static NTSTATUS dcesrv_lsa_EnumTrustDom(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_EnumTrustDom *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_DomainInfo *entries;
	struct lsa_policy_state *policy_state;
	struct ldb_message **domains;
	const char *attrs[] = {
		"flatname",
		"securityIdentifier",
		NULL
	};


	int count, i;

	*r->out.resume_handle = 0;

	r->out.domains->domains = NULL;
	r->out.domains->count = 0;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	policy_state = policy_handle->data;

	/* search for all users in this domain. This could possibly be cached and
	   resumed based on resume_key */
	count = gendb_search(policy_state->sam_ldb, mem_ctx, policy_state->system_dn, &domains, attrs,
			     "objectclass=trustedDomain");
	if (count < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* convert to lsa_TrustInformation format */
	entries = talloc_array(mem_ctx, struct lsa_DomainInfo, count);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<count;i++) {
		entries[i].sid = samdb_result_dom_sid(mem_ctx, domains[i], "securityIdentifier");
		entries[i].name.string = ldb_msg_find_attr_as_string(domains[i], "flatname", NULL);
	}

	/* sort the results by name */
	TYPESAFE_QSORT(entries, count, compare_DomainInfo);

	if (*r->in.resume_handle >= count) {
		*r->out.resume_handle = -1;

		return NT_STATUS_NO_MORE_ENTRIES;
	}

	/* return the rest, limit by max_size. Note that we
	   use the w2k3 element size value of 60 */
	r->out.domains->count = count - *r->in.resume_handle;
	r->out.domains->count = MIN(r->out.domains->count,
				 1+(r->in.max_size/LSA_ENUM_TRUST_DOMAIN_MULTIPLIER));

	r->out.domains->domains = entries + *r->in.resume_handle;
	r->out.domains->count = r->out.domains->count;

	if (r->out.domains->count < count - *r->in.resume_handle) {
		*r->out.resume_handle = *r->in.resume_handle + r->out.domains->count;
		return STATUS_MORE_ENTRIES;
	}

	/* according to MS-LSAD 3.1.4.7.8 output resume handle MUST
	 * always be larger than the previous input resume handle, in
	 * particular when hitting the last query it is vital to set the
	 * resume handle correctly to avoid infinite client loops, as
	 * seen e.g. with Windows XP SP3 when resume handle is 0 and
	 * status is NT_STATUS_OK - gd */

	*r->out.resume_handle = (uint32_t)-1;

	return NT_STATUS_OK;
}

/*
  comparison function for sorting lsa_DomainInformation array
*/
static int compare_TrustDomainInfoInfoEx(struct lsa_TrustDomainInfoInfoEx *e1, struct lsa_TrustDomainInfoInfoEx *e2)
{
	return strcasecmp_m(e1->netbios_name.string, e2->netbios_name.string);
}

/*
  lsa_EnumTrustedDomainsEx
*/
static NTSTATUS dcesrv_lsa_EnumTrustedDomainsEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct lsa_EnumTrustedDomainsEx *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_TrustDomainInfoInfoEx *entries;
	struct lsa_policy_state *policy_state;
	struct ldb_message **domains;
	const char *attrs[] = {
		"flatname",
		"trustPartner",
		"securityIdentifier",
		"trustDirection",
		"trustType",
		"trustAttributes",
		NULL
	};
	NTSTATUS nt_status;

	int count, i;

	*r->out.resume_handle = 0;

	r->out.domains->domains = NULL;
	r->out.domains->count = 0;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	policy_state = policy_handle->data;

	/* search for all users in this domain. This could possibly be cached and
	   resumed based on resume_key */
	count = gendb_search(policy_state->sam_ldb, mem_ctx, policy_state->system_dn, &domains, attrs,
			     "objectclass=trustedDomain");
	if (count < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* convert to lsa_DomainInformation format */
	entries = talloc_array(mem_ctx, struct lsa_TrustDomainInfoInfoEx, count);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<count;i++) {
		nt_status = fill_trust_domain_ex(mem_ctx, domains[i], &entries[i]);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}

	/* sort the results by name */
	TYPESAFE_QSORT(entries, count, compare_TrustDomainInfoInfoEx);

	if (*r->in.resume_handle >= count) {
		*r->out.resume_handle = -1;

		return NT_STATUS_NO_MORE_ENTRIES;
	}

	/* return the rest, limit by max_size. Note that we
	   use the w2k3 element size value of 60 */
	r->out.domains->count = count - *r->in.resume_handle;
	r->out.domains->count = MIN(r->out.domains->count,
				 1+(r->in.max_size/LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER));

	r->out.domains->domains = entries + *r->in.resume_handle;
	r->out.domains->count = r->out.domains->count;

	if (r->out.domains->count < count - *r->in.resume_handle) {
		*r->out.resume_handle = *r->in.resume_handle + r->out.domains->count;
		return STATUS_MORE_ENTRIES;
	}

	*r->out.resume_handle = *r->in.resume_handle + r->out.domains->count;

	return NT_STATUS_OK;
}


/*
  lsa_OpenAccount
*/
static NTSTATUS dcesrv_lsa_OpenAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_OpenAccount *r)
{
	struct dcesrv_handle *h, *ah;
	struct lsa_policy_state *state;
	struct lsa_account_state *astate;

	ZERO_STRUCTP(r->out.acct_handle);

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	astate = talloc(dce_call->conn, struct lsa_account_state);
	if (astate == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	astate->account_sid = dom_sid_dup(astate, r->in.sid);
	if (astate->account_sid == NULL) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}

	astate->policy = talloc_reference(astate, state);
	astate->access_mask = r->in.access_mask;

	/*
	 * For now we grant all requested access.
	 *
	 * We will fail at the ldb layer later.
	 */
	if (astate->access_mask & SEC_FLAG_MAXIMUM_ALLOWED) {
		astate->access_mask &= ~SEC_FLAG_MAXIMUM_ALLOWED;
		astate->access_mask |= LSA_ACCOUNT_ALL_ACCESS;
	}
	se_map_generic(&astate->access_mask, &dcesrv_lsa_account_mapping);

	DEBUG(10,("%s: %s access desired[0x%08X] granted[0x%08X] - success.\n",
		  __func__, dom_sid_string(mem_ctx, astate->account_sid),
		 (unsigned)r->in.access_mask,
		 (unsigned)astate->access_mask));

	ah = dcesrv_handle_new(dce_call->context, LSA_HANDLE_ACCOUNT);
	if (!ah) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}

	ah->data = talloc_steal(ah, astate);

	*r->out.acct_handle = ah->wire_handle;

	return NT_STATUS_OK;
}


/*
  lsa_EnumPrivsAccount
*/
static NTSTATUS dcesrv_lsa_EnumPrivsAccount(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx,
				     struct lsa_EnumPrivsAccount *r)
{
	struct dcesrv_handle *h;
	struct lsa_account_state *astate;
	int ret;
	unsigned int i, j;
	struct ldb_message **res;
	const char * const attrs[] = { "privilege", NULL};
	struct ldb_message_element *el;
	const char *sidstr;
	struct lsa_PrivilegeSet *privs;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

	astate = h->data;

	privs = talloc(mem_ctx, struct lsa_PrivilegeSet);
	if (privs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	privs->count = 0;
	privs->unknown = 0;
	privs->set = NULL;

	*r->out.privs = privs;

	sidstr = ldap_encode_ndr_dom_sid(mem_ctx, astate->account_sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(astate->policy->pdb, mem_ctx, NULL, &res, attrs,
			   "objectSid=%s", sidstr);
	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ret != 1) {
		return NT_STATUS_OK;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL || el->num_values == 0) {
		return NT_STATUS_OK;
	}

	privs->set = talloc_array(privs,
				  struct lsa_LUIDAttribute, el->num_values);
	if (privs->set == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	j = 0;
	for (i=0;i<el->num_values;i++) {
		int id = sec_privilege_id((const char *)el->values[i].data);
		if (id == SEC_PRIV_INVALID) {
			/* Perhaps an account right, not a privilege */
			continue;
		}
		privs->set[j].attribute = 0;
		privs->set[j].luid.low = id;
		privs->set[j].luid.high = 0;
		j++;
	}

	privs->count = j;

	return NT_STATUS_OK;
}

/*
  lsa_EnumAccountRights
*/
static NTSTATUS dcesrv_lsa_EnumAccountRights(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx,
				      struct lsa_EnumAccountRights *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int ret;
	unsigned int i;
	struct ldb_message **res;
	const char * const attrs[] = { "privilege", NULL};
	const char *sidstr;
	struct ldb_message_element *el;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	sidstr = ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(state->pdb, mem_ctx, NULL, &res, attrs,
			   "(&(objectSid=%s)(privilege=*))", sidstr);
	if (ret == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (ret != 1) {
		DEBUG(3, ("searching for account rights for SID: %s failed: %s",
			  dom_sid_string(mem_ctx, r->in.sid),
			  ldb_errstring(state->pdb)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL || el->num_values == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	r->out.rights->count = el->num_values;
	r->out.rights->names = talloc_array(r->out.rights,
					    struct lsa_StringLarge, r->out.rights->count);
	if (r->out.rights->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<el->num_values;i++) {
		r->out.rights->names[i].string = (const char *)el->values[i].data;
	}

	return NT_STATUS_OK;
}



/*
  helper for lsa_AddAccountRights and lsa_RemoveAccountRights
*/
static NTSTATUS dcesrv_lsa_AddRemoveAccountRights(struct dcesrv_call_state *dce_call,
					   TALLOC_CTX *mem_ctx,
					   struct lsa_policy_state *state,
					   int ldb_flag,
					   struct dom_sid *sid,
					   const struct lsa_RightSet *rights)
{
	const char *sidstr, *sidndrstr;
	struct ldb_message *msg;
	struct ldb_message_element *el;
	int ret;
	uint32_t i;
	struct lsa_EnumAccountRights r2;
	char *dnstr;

	if (security_session_user_level(dce_call->conn->auth_state.session_info, NULL) <
	    SECURITY_ADMINISTRATOR) {
		DEBUG(0,("lsa_AddRemoveAccount refused for supplied security token\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sidndrstr = ldap_encode_ndr_dom_sid(msg, sid);
	if (sidndrstr == NULL) {
		TALLOC_FREE(msg);
		return NT_STATUS_NO_MEMORY;
	}

	sidstr = dom_sid_string(msg, sid);
	if (sidstr == NULL) {
		TALLOC_FREE(msg);
		return NT_STATUS_NO_MEMORY;
	}

	dnstr = talloc_asprintf(msg, "sid=%s", sidstr);
	if (dnstr == NULL) {
		TALLOC_FREE(msg);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_new(msg, state->pdb, dnstr);
	if (msg->dn == NULL) {
		TALLOC_FREE(msg);
		return NT_STATUS_NO_MEMORY;
	}

	if (LDB_FLAG_MOD_TYPE(ldb_flag) == LDB_FLAG_MOD_ADD) {
		NTSTATUS status;

		r2.in.handle = &state->handle->wire_handle;
		r2.in.sid = sid;
		r2.out.rights = talloc(mem_ctx, struct lsa_RightSet);

		status = dcesrv_lsa_EnumAccountRights(dce_call, mem_ctx, &r2);
		if (!NT_STATUS_IS_OK(status)) {
			ZERO_STRUCTP(r2.out.rights);
		}
	}

	for (i=0;i<rights->count;i++) {
		if (sec_privilege_id(rights->names[i].string) == SEC_PRIV_INVALID) {
			if (sec_right_bit(rights->names[i].string) == 0) {
				talloc_free(msg);
				return NT_STATUS_NO_SUCH_PRIVILEGE;
			}

			talloc_free(msg);
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}

		if (LDB_FLAG_MOD_TYPE(ldb_flag) == LDB_FLAG_MOD_ADD) {
			uint32_t j;
			for (j=0;j<r2.out.rights->count;j++) {
				if (strcasecmp_m(r2.out.rights->names[j].string,
					       rights->names[i].string) == 0) {
					break;
				}
			}
			if (j != r2.out.rights->count) continue;
		}

		ret = ldb_msg_add_string(msg, "privilege", rights->names[i].string);
		if (ret != LDB_SUCCESS) {
			talloc_free(msg);
			return NT_STATUS_NO_MEMORY;
		}
	}

	el = ldb_msg_find_element(msg, "privilege");
	if (!el) {
		talloc_free(msg);
		return NT_STATUS_OK;
	}

	el->flags = ldb_flag;

	ret = ldb_modify(state->pdb, msg);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		if (samdb_msg_add_dom_sid(state->pdb, msg, msg, "objectSid", sid) != LDB_SUCCESS) {
			talloc_free(msg);
			return NT_STATUS_NO_MEMORY;
		}
		ldb_msg_add_string(msg, "comment", "added via LSA");
		ret = ldb_add(state->pdb, msg);
	}
	if (ret != LDB_SUCCESS) {
		if (LDB_FLAG_MOD_TYPE(ldb_flag) == LDB_FLAG_MOD_DELETE && ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
			talloc_free(msg);
			return NT_STATUS_OK;
		}
		DEBUG(3, ("Could not %s attributes from %s: %s",
			  LDB_FLAG_MOD_TYPE(ldb_flag) == LDB_FLAG_MOD_DELETE ? "delete" : "add",
			  ldb_dn_get_linearized(msg->dn), ldb_errstring(state->pdb)));
		talloc_free(msg);
		return NT_STATUS_UNEXPECTED_IO_ERROR;
	}

	talloc_free(msg);
	return NT_STATUS_OK;
}

/*
  lsa_AddPrivilegesToAccount
*/
static NTSTATUS dcesrv_lsa_AddPrivilegesToAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					   struct lsa_AddPrivilegesToAccount *r)
{
	struct lsa_RightSet rights;
	struct dcesrv_handle *h;
	struct lsa_account_state *astate;
	uint32_t i;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

	astate = h->data;

	rights.count = r->in.privs->count;
	rights.names = talloc_array(mem_ctx, struct lsa_StringLarge, rights.count);
	if (rights.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<rights.count;i++) {
		int id = r->in.privs->set[i].luid.low;
		if (r->in.privs->set[i].luid.high) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
		rights.names[i].string = sec_privilege_name(id);
		if (rights.names[i].string == NULL) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
	}

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy,
					  LDB_FLAG_MOD_ADD, astate->account_sid,
					  &rights);
}


/*
  lsa_RemovePrivilegesFromAccount
*/
static NTSTATUS dcesrv_lsa_RemovePrivilegesFromAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct lsa_RemovePrivilegesFromAccount *r)
{
	struct lsa_RightSet *rights;
	struct dcesrv_handle *h;
	struct lsa_account_state *astate;
	uint32_t i;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

	astate = h->data;

	rights = talloc(mem_ctx, struct lsa_RightSet);

	if (r->in.remove_all == 1 &&
	    r->in.privs == NULL) {
		struct lsa_EnumAccountRights r2;
		NTSTATUS status;

		r2.in.handle = &astate->policy->handle->wire_handle;
		r2.in.sid = astate->account_sid;
		r2.out.rights = rights;

		status = dcesrv_lsa_EnumAccountRights(dce_call, mem_ctx, &r2);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy,
						  LDB_FLAG_MOD_DELETE, astate->account_sid,
						  r2.out.rights);
	}

	if (r->in.remove_all != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	rights->count = r->in.privs->count;
	rights->names = talloc_array(mem_ctx, struct lsa_StringLarge, rights->count);
	if (rights->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<rights->count;i++) {
		int id = r->in.privs->set[i].luid.low;
		if (r->in.privs->set[i].luid.high) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
		rights->names[i].string = sec_privilege_name(id);
		if (rights->names[i].string == NULL) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
	}

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy,
					  LDB_FLAG_MOD_DELETE, astate->account_sid,
					  rights);
}


/*
  lsa_GetQuotasForAccount
*/
static NTSTATUS dcesrv_lsa_GetQuotasForAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_GetQuotasForAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_SetQuotasForAccount
*/
static NTSTATUS dcesrv_lsa_SetQuotasForAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetQuotasForAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_GetSystemAccessAccount
*/
static NTSTATUS dcesrv_lsa_GetSystemAccessAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_GetSystemAccessAccount *r)
{
	struct dcesrv_handle *h;
	struct lsa_account_state *astate;
	int ret;
	unsigned int i;
	struct ldb_message **res;
	const char * const attrs[] = { "privilege", NULL};
	struct ldb_message_element *el;
	const char *sidstr;

	*(r->out.access_mask) = 0x00000000;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

	astate = h->data;

	sidstr = ldap_encode_ndr_dom_sid(mem_ctx, astate->account_sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(astate->policy->pdb, mem_ctx, NULL, &res, attrs,
			   "objectSid=%s", sidstr);
	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ret != 1) {
		return NT_STATUS_OK;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL || el->num_values == 0) {
		return NT_STATUS_OK;
	}

	for (i=0;i<el->num_values;i++) {
		uint32_t right_bit = sec_right_bit((const char *)el->values[i].data);
		if (right_bit == 0) {
			/* Perhaps an privilege, not a right */
			continue;
		}
		*(r->out.access_mask) |= right_bit;
	}

	return NT_STATUS_OK;
}


/*
  lsa_SetSystemAccessAccount
*/
static NTSTATUS dcesrv_lsa_SetSystemAccessAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetSystemAccessAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CreateSecret
*/
static NTSTATUS dcesrv_lsa_CreateSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_CreateSecret *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_policy_state *policy_state;
	struct lsa_secret_state *secret_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs, *msg;
	const char *attrs[] = {
		NULL
	};

	const char *name;

	int ret;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.sec_handle);

	switch (security_session_user_level(dce_call->conn->auth_state.session_info, NULL))
	{
	case SECURITY_SYSTEM:
	case SECURITY_ADMINISTRATOR:
		break;
	default:
		/* Users and annonymous are not allowed create secrets */
		return NT_STATUS_ACCESS_DENIED;
	}

	policy_state = policy_handle->data;

	if (!r->in.name.string) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	secret_state = talloc(mem_ctx, struct lsa_secret_state);
	NT_STATUS_HAVE_NO_MEMORY(secret_state);
	secret_state->policy = policy_state;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (strncmp("G$", r->in.name.string, 2) == 0) {
		const char *name2;

		secret_state->global = true;

		name = &r->in.name.string[2];
		if (strlen(name) == 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		name2 = talloc_asprintf(mem_ctx, "%s Secret",
					ldb_binary_encode_string(mem_ctx, name));
		NT_STATUS_HAVE_NO_MEMORY(name2);

		/* We need to connect to the database as system, as this is one
		 * of the rare RPC calls that must read the secrets (and this
		 * is denied otherwise) */
		secret_state->sam_ldb = talloc_reference(secret_state,
							 samdb_connect(mem_ctx, dce_call->event_ctx, dce_call->conn->dce_ctx->lp_ctx, system_session(dce_call->conn->dce_ctx->lp_ctx), 0));
		NT_STATUS_HAVE_NO_MEMORY(secret_state->sam_ldb);

		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb,
				   mem_ctx, policy_state->system_dn, &msgs, attrs,
				   "(&(cn=%s)(objectclass=secret))",
				   name2);
		if (ret > 0) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		if (ret < 0) {
			DEBUG(0,("Failure searching for CN=%s: %s\n",
				 name2, ldb_errstring(secret_state->sam_ldb)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		msg->dn = ldb_dn_copy(mem_ctx, policy_state->system_dn);
		NT_STATUS_HAVE_NO_MEMORY(msg->dn);
		if (!ldb_dn_add_child_fmt(msg->dn, "cn=%s", name2)) {
			return NT_STATUS_NO_MEMORY;
		}

		ret = ldb_msg_add_string(msg, "cn", name2);
		if (ret != LDB_SUCCESS) return NT_STATUS_NO_MEMORY;
	} else {
		secret_state->global = false;

		name = r->in.name.string;
		if (strlen(name) == 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		secret_state->sam_ldb = talloc_reference(secret_state,
							 secrets_db_connect(mem_ctx, dce_call->conn->dce_ctx->lp_ctx));
		NT_STATUS_HAVE_NO_MEMORY(secret_state->sam_ldb);

		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb, mem_ctx,
				   ldb_dn_new(mem_ctx, secret_state->sam_ldb, "cn=LSA Secrets"),
				   &msgs, attrs,
				   "(&(cn=%s)(objectclass=secret))",
				   ldb_binary_encode_string(mem_ctx, name));
		if (ret > 0) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		if (ret < 0) {
			DEBUG(0,("Failure searching for CN=%s: %s\n",
				 name, ldb_errstring(secret_state->sam_ldb)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		msg->dn = ldb_dn_new_fmt(mem_ctx, secret_state->sam_ldb,
					 "cn=%s,cn=LSA Secrets", name);
		NT_STATUS_HAVE_NO_MEMORY(msg->dn);
		ret = ldb_msg_add_string(msg, "cn", name);
		if (ret != LDB_SUCCESS) return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_msg_add_string(msg, "objectClass", "secret");
	if (ret != LDB_SUCCESS) return NT_STATUS_NO_MEMORY;

	secret_state->secret_dn = talloc_reference(secret_state, msg->dn);
	NT_STATUS_HAVE_NO_MEMORY(secret_state->secret_dn);

	/* create the secret */
	ret = ldb_add(secret_state->sam_ldb, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to create secret record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(secret_state->sam_ldb)));
		return NT_STATUS_ACCESS_DENIED;
	}

	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_SECRET);
	NT_STATUS_HAVE_NO_MEMORY(handle);

	handle->data = talloc_steal(handle, secret_state);

	secret_state->access_mask = r->in.access_mask;
	secret_state->policy = talloc_reference(secret_state, policy_state);
	NT_STATUS_HAVE_NO_MEMORY(secret_state->policy);

	*r->out.sec_handle = handle->wire_handle;

	return NT_STATUS_OK;
}


/*
  lsa_OpenSecret
*/
static NTSTATUS dcesrv_lsa_OpenSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct lsa_OpenSecret *r)
{
	struct dcesrv_handle *policy_handle;

	struct lsa_policy_state *policy_state;
	struct lsa_secret_state *secret_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs;
	const char *attrs[] = {
		NULL
	};

	const char *name;

	int ret;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.sec_handle);
	policy_state = policy_handle->data;

	if (!r->in.name.string) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (security_session_user_level(dce_call->conn->auth_state.session_info, NULL))
	{
	case SECURITY_SYSTEM:
	case SECURITY_ADMINISTRATOR:
		break;
	default:
		/* Users and annonymous are not allowed to access secrets */
		return NT_STATUS_ACCESS_DENIED;
	}

	secret_state = talloc(mem_ctx, struct lsa_secret_state);
	if (!secret_state) {
		return NT_STATUS_NO_MEMORY;
	}
	secret_state->policy = policy_state;

	if (strncmp("G$", r->in.name.string, 2) == 0) {
		name = &r->in.name.string[2];
		/* We need to connect to the database as system, as this is one of the rare RPC calls that must read the secrets (and this is denied otherwise) */
		secret_state->sam_ldb = talloc_reference(secret_state,
							 samdb_connect(mem_ctx, dce_call->event_ctx, dce_call->conn->dce_ctx->lp_ctx, system_session(dce_call->conn->dce_ctx->lp_ctx), 0));
		secret_state->global = true;

		if (strlen(name) < 1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb,
				   mem_ctx, policy_state->system_dn, &msgs, attrs,
				   "(&(cn=%s Secret)(objectclass=secret))",
				   ldb_binary_encode_string(mem_ctx, name));
		if (ret == 0) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (ret != 1) {
			DEBUG(0,("Found %d records matching DN %s\n", ret,
				 ldb_dn_get_linearized(policy_state->system_dn)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else {
		secret_state->global = false;
		secret_state->sam_ldb = talloc_reference(secret_state,
							 secrets_db_connect(mem_ctx, dce_call->conn->dce_ctx->lp_ctx));

		name = r->in.name.string;
		if (strlen(name) < 1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb, mem_ctx,
				   ldb_dn_new(mem_ctx, secret_state->sam_ldb, "cn=LSA Secrets"),
				   &msgs, attrs,
				   "(&(cn=%s)(objectclass=secret))",
				   ldb_binary_encode_string(mem_ctx, name));
		if (ret == 0) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (ret != 1) {
			DEBUG(0,("Found %d records matching CN=%s\n",
				 ret, ldb_binary_encode_string(mem_ctx, name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	secret_state->secret_dn = talloc_reference(secret_state, msgs[0]->dn);

	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_SECRET);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = talloc_steal(handle, secret_state);

	secret_state->access_mask = r->in.access_mask;
	secret_state->policy = talloc_reference(secret_state, policy_state);

	*r->out.sec_handle = handle->wire_handle;

	return NT_STATUS_OK;
}


/*
  lsa_SetSecret
*/
static NTSTATUS dcesrv_lsa_SetSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct lsa_SetSecret *r)
{

	struct dcesrv_handle *h;
	struct lsa_secret_state *secret_state;
	struct ldb_message *msg;
	DATA_BLOB session_key;
	DATA_BLOB crypt_secret, secret;
	struct ldb_val val;
	int ret;
	NTSTATUS status = NT_STATUS_OK;

	struct timeval now = timeval_current();
	NTTIME nt_now = timeval_to_nttime(&now);

	DCESRV_PULL_HANDLE(h, r->in.sec_handle, LSA_HANDLE_SECRET);

	secret_state = h->data;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_reference(mem_ctx, secret_state->secret_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_fetch_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (r->in.old_val) {
		/* Decrypt */
		crypt_secret.data = r->in.old_val->data;
		crypt_secret.length = r->in.old_val->size;

		status = sess_decrypt_blob(mem_ctx, &crypt_secret, &session_key, &secret);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		val.data = secret.data;
		val.length = secret.length;

		/* set value */
		if (ldb_msg_add_value(msg, "priorValue", &val, NULL) != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}

		/* set old value mtime */
		if (samdb_msg_add_uint64(secret_state->sam_ldb,
					 mem_ctx, msg, "priorSetTime", nt_now) != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}

	} else {
		/* If the old value is not set, then migrate the
		 * current value to the old value */
		const struct ldb_val *old_val;
		NTTIME last_set_time;
		struct ldb_message **res;
		const char *attrs[] = {
			"currentValue",
			"lastSetTime",
			NULL
		};

		/* search for the secret record */
		ret = gendb_search_dn(secret_state->sam_ldb,mem_ctx,
				      secret_state->secret_dn, &res, attrs);
		if (ret == 0) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (ret != 1) {
			DEBUG(0,("Found %d records matching dn=%s\n", ret,
				 ldb_dn_get_linearized(secret_state->secret_dn)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		old_val = ldb_msg_find_ldb_val(res[0], "currentValue");
		last_set_time = ldb_msg_find_attr_as_uint64(res[0], "lastSetTime", 0);

		if (old_val) {
			/* set old value */
			if (ldb_msg_add_value(msg, "priorValue",
					      old_val, NULL) != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			if (samdb_msg_add_delete(secret_state->sam_ldb,
						 mem_ctx, msg, "priorValue") != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		/* set old value mtime */
		if (ldb_msg_find_ldb_val(res[0], "lastSetTime")) {
			if (samdb_msg_add_uint64(secret_state->sam_ldb,
						 mem_ctx, msg, "priorSetTime", last_set_time) != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			if (samdb_msg_add_uint64(secret_state->sam_ldb,
						 mem_ctx, msg, "priorSetTime", nt_now) != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		}
	}

	if (r->in.new_val) {
		/* Decrypt */
		crypt_secret.data = r->in.new_val->data;
		crypt_secret.length = r->in.new_val->size;

		status = sess_decrypt_blob(mem_ctx, &crypt_secret, &session_key, &secret);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		val.data = secret.data;
		val.length = secret.length;

		/* set value */
		if (ldb_msg_add_value(msg, "currentValue", &val, NULL) != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}

		/* set new value mtime */
		if (samdb_msg_add_uint64(secret_state->sam_ldb,
					 mem_ctx, msg, "lastSetTime", nt_now) != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		/* NULL out the NEW value */
		if (samdb_msg_add_uint64(secret_state->sam_ldb,
					 mem_ctx, msg, "lastSetTime", nt_now) != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
		if (samdb_msg_add_delete(secret_state->sam_ldb,
					 mem_ctx, msg, "currentValue") != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* modify the samdb record */
	ret = dsdb_replace(secret_state->sam_ldb, msg, 0);
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	return NT_STATUS_OK;
}


/*
  lsa_QuerySecret
*/
static NTSTATUS dcesrv_lsa_QuerySecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_QuerySecret *r)
{
	struct dcesrv_handle *h;
	struct lsa_secret_state *secret_state;
	struct ldb_message *msg;
	DATA_BLOB session_key;
	DATA_BLOB crypt_secret, secret;
	int ret;
	struct ldb_message **res;
	const char *attrs[] = {
		"currentValue",
		"priorValue",
		"lastSetTime",
		"priorSetTime",
		NULL
	};

	NTSTATUS nt_status;

	DCESRV_PULL_HANDLE(h, r->in.sec_handle, LSA_HANDLE_SECRET);

	/* Ensure user is permitted to read this... */
	switch (security_session_user_level(dce_call->conn->auth_state.session_info, NULL))
	{
	case SECURITY_SYSTEM:
	case SECURITY_ADMINISTRATOR:
		break;
	default:
		/* Users and annonymous are not allowed to read secrets */
		return NT_STATUS_ACCESS_DENIED;
	}

	secret_state = h->data;

	/* pull all the user attributes */
	ret = gendb_search_dn(secret_state->sam_ldb, mem_ctx,
			      secret_state->secret_dn, &res, attrs);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	nt_status = dcesrv_fetch_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (r->in.old_val) {
		const struct ldb_val *prior_val;
		r->out.old_val = talloc_zero(mem_ctx, struct lsa_DATA_BUF_PTR);
		if (!r->out.old_val) {
			return NT_STATUS_NO_MEMORY;
		}
		prior_val = ldb_msg_find_ldb_val(msg, "priorValue");

		if (prior_val && prior_val->length) {
			secret.data = prior_val->data;
			secret.length = prior_val->length;

			/* Encrypt */
			crypt_secret = sess_encrypt_blob(mem_ctx, &secret, &session_key);
			if (!crypt_secret.length) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.old_val->buf = talloc(mem_ctx, struct lsa_DATA_BUF);
			if (!r->out.old_val->buf) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.old_val->buf->size = crypt_secret.length;
			r->out.old_val->buf->length = crypt_secret.length;
			r->out.old_val->buf->data = crypt_secret.data;
		}
	}

	if (r->in.old_mtime) {
		r->out.old_mtime = talloc(mem_ctx, NTTIME);
		if (!r->out.old_mtime) {
			return NT_STATUS_NO_MEMORY;
		}
		*r->out.old_mtime = ldb_msg_find_attr_as_uint64(msg, "priorSetTime", 0);
	}

	if (r->in.new_val) {
		const struct ldb_val *new_val;
		r->out.new_val = talloc_zero(mem_ctx, struct lsa_DATA_BUF_PTR);
		if (!r->out.new_val) {
			return NT_STATUS_NO_MEMORY;
		}

		new_val = ldb_msg_find_ldb_val(msg, "currentValue");

		if (new_val && new_val->length) {
			secret.data = new_val->data;
			secret.length = new_val->length;

			/* Encrypt */
			crypt_secret = sess_encrypt_blob(mem_ctx, &secret, &session_key);
			if (!crypt_secret.length) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.new_val->buf = talloc(mem_ctx, struct lsa_DATA_BUF);
			if (!r->out.new_val->buf) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.new_val->buf->length = crypt_secret.length;
			r->out.new_val->buf->size = crypt_secret.length;
			r->out.new_val->buf->data = crypt_secret.data;
		}
	}

	if (r->in.new_mtime) {
		r->out.new_mtime = talloc(mem_ctx, NTTIME);
		if (!r->out.new_mtime) {
			return NT_STATUS_NO_MEMORY;
		}
		*r->out.new_mtime = ldb_msg_find_attr_as_uint64(msg, "lastSetTime", 0);
	}

	return NT_STATUS_OK;
}


/*
  lsa_LookupPrivValue
*/
static NTSTATUS dcesrv_lsa_LookupPrivValue(struct dcesrv_call_state *dce_call,
				    TALLOC_CTX *mem_ctx,
				    struct lsa_LookupPrivValue *r)
{
	struct dcesrv_handle *h;
	int id;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	id = sec_privilege_id(r->in.name->string);
	if (id == SEC_PRIV_INVALID) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	r->out.luid->low = id;
	r->out.luid->high = 0;

	return NT_STATUS_OK;
}


/*
  lsa_LookupPrivName
*/
static NTSTATUS dcesrv_lsa_LookupPrivName(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx,
				   struct lsa_LookupPrivName *r)
{
	struct dcesrv_handle *h;
	struct lsa_StringLarge *name;
	const char *privname;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	if (r->in.luid->high != 0) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	privname = sec_privilege_name(r->in.luid->low);
	if (privname == NULL) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	name = talloc(mem_ctx, struct lsa_StringLarge);
	if (name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	name->string = privname;

	*r->out.name = name;

	return NT_STATUS_OK;
}


/*
  lsa_LookupPrivDisplayName
*/
static NTSTATUS dcesrv_lsa_LookupPrivDisplayName(struct dcesrv_call_state *dce_call,
					  TALLOC_CTX *mem_ctx,
					  struct lsa_LookupPrivDisplayName *r)
{
	struct dcesrv_handle *h;
	struct lsa_StringLarge *disp_name = NULL;
	enum sec_privilege id;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	id = sec_privilege_id(r->in.name->string);
	if (id == SEC_PRIV_INVALID) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	disp_name = talloc(mem_ctx, struct lsa_StringLarge);
	if (disp_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	disp_name->string = sec_privilege_display_name(id, &r->in.language_id);
	if (disp_name->string == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	*r->out.disp_name = disp_name;
	*r->out.returned_language_id = 0;

	return NT_STATUS_OK;
}


/*
  lsa_EnumAccountsWithUserRight
*/
static NTSTATUS dcesrv_lsa_EnumAccountsWithUserRight(struct dcesrv_call_state *dce_call,
					      TALLOC_CTX *mem_ctx,
					      struct lsa_EnumAccountsWithUserRight *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int ret, i;
	struct ldb_message **res;
	const char * const attrs[] = { "objectSid", NULL};
	const char *privname;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	if (r->in.name == NULL) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	privname = r->in.name->string;
	if (sec_privilege_id(privname) == SEC_PRIV_INVALID && sec_right_bit(privname) == 0) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	ret = gendb_search(state->pdb, mem_ctx, NULL, &res, attrs,
			   "privilege=%s", privname);
	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ret == 0) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	r->out.sids->sids = talloc_array(r->out.sids, struct lsa_SidPtr, ret);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<ret;i++) {
		r->out.sids->sids[i].sid = samdb_result_dom_sid(r->out.sids->sids,
								res[i], "objectSid");
		NT_STATUS_HAVE_NO_MEMORY(r->out.sids->sids[i].sid);
	}
	r->out.sids->num_sids = ret;

	return NT_STATUS_OK;
}


/*
  lsa_AddAccountRights
*/
static NTSTATUS dcesrv_lsa_AddAccountRights(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx,
				     struct lsa_AddAccountRights *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, state,
					  LDB_FLAG_MOD_ADD,
					  r->in.sid, r->in.rights);
}


/*
  lsa_RemoveAccountRights
*/
static NTSTATUS dcesrv_lsa_RemoveAccountRights(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx,
					struct lsa_RemoveAccountRights *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, state,
					  LDB_FLAG_MOD_DELETE,
					  r->in.sid, r->in.rights);
}


/*
  lsa_StorePrivateData
*/
static NTSTATUS dcesrv_lsa_StorePrivateData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_StorePrivateData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_RetrievePrivateData
*/
static NTSTATUS dcesrv_lsa_RetrievePrivateData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_RetrievePrivateData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_GetUserName
*/
static NTSTATUS dcesrv_lsa_GetUserName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_GetUserName *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	NTSTATUS status = NT_STATUS_OK;
	const char *account_name;
	const char *authority_name;
	struct lsa_String *_account_name;
	struct lsa_String *_authority_name = NULL;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	/* this is what w2k3 does */
	r->out.account_name = r->in.account_name;
	r->out.authority_name = r->in.authority_name;

	if (r->in.account_name
	    && *r->in.account_name
	    /* && *(*r->in.account_name)->string */
	    ) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.authority_name
	    && *r->in.authority_name
	    /* && *(*r->in.authority_name)->string */
	    ) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	account_name = talloc_reference(mem_ctx, dce_call->conn->auth_state.session_info->info->account_name);
	authority_name = talloc_reference(mem_ctx, dce_call->conn->auth_state.session_info->info->domain_name);

	_account_name = talloc(mem_ctx, struct lsa_String);
	NT_STATUS_HAVE_NO_MEMORY(_account_name);
	_account_name->string = account_name;

	if (r->in.authority_name) {
		_authority_name = talloc(mem_ctx, struct lsa_String);
		NT_STATUS_HAVE_NO_MEMORY(_authority_name);
		_authority_name->string = authority_name;
	}

	*r->out.account_name = _account_name;
	if (r->out.authority_name) {
		*r->out.authority_name = _authority_name;
	}

	return status;
}

/*
  lsa_SetInfoPolicy2
*/
static NTSTATUS dcesrv_lsa_SetInfoPolicy2(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx,
				   struct lsa_SetInfoPolicy2 *r)
{
	/* need to support these */
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

static void kdc_get_policy(struct loadparm_context *lp_ctx,
			   struct smb_krb5_context *smb_krb5_context,
			   struct lsa_DomainInfoKerberos *k)
{
	time_t svc_tkt_lifetime;
	time_t usr_tkt_lifetime;
	time_t renewal_lifetime;

	/* These should be set and stored via Group Policy, but until then, some defaults are in order */

	/* Our KDC always re-validates the client */
	k->authentication_options = LSA_POLICY_KERBEROS_VALIDATE_CLIENT;

	lpcfg_default_kdc_policy(lp_ctx, &svc_tkt_lifetime,
				 &usr_tkt_lifetime, &renewal_lifetime);

	unix_to_nt_time(&k->service_tkt_lifetime, svc_tkt_lifetime);
	unix_to_nt_time(&k->user_tkt_lifetime, usr_tkt_lifetime);
	unix_to_nt_time(&k->user_tkt_renewaltime, renewal_lifetime);
#ifdef SAMBA4_USES_HEIMDAL /* MIT lacks krb5_get_max_time_skew.
	However in the parent function we basically just did a full
	krb5_context init with the only purpose of getting a global
	config option (the max skew), it would probably make more sense
	to have a lp_ or ldb global option as the samba default */
	if (smb_krb5_context) {
		unix_to_nt_time(&k->clock_skew,
				krb5_get_max_time_skew(smb_krb5_context->krb5_context));
	}
#endif
	k->reserved = 0;
}
/*
  lsa_QueryDomainInformationPolicy
*/
static NTSTATUS dcesrv_lsa_QueryDomainInformationPolicy(struct dcesrv_call_state *dce_call,
						 TALLOC_CTX *mem_ctx,
						 struct lsa_QueryDomainInformationPolicy *r)
{
	union lsa_DomainInformationPolicy *info;

	info = talloc_zero(r->out.info, union lsa_DomainInformationPolicy);
	if (!info) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case LSA_DOMAIN_INFO_POLICY_EFS:
		talloc_free(info);
		*r->out.info = NULL;
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	case LSA_DOMAIN_INFO_POLICY_KERBEROS:
	{
		struct lsa_DomainInfoKerberos *k = &info->kerberos_info;
		struct smb_krb5_context *smb_krb5_context;
		int ret = smb_krb5_init_context(mem_ctx,
							dce_call->conn->dce_ctx->lp_ctx,
							&smb_krb5_context);
		if (ret != 0) {
			talloc_free(info);
			*r->out.info = NULL;
			return NT_STATUS_INTERNAL_ERROR;
		}
		kdc_get_policy(dce_call->conn->dce_ctx->lp_ctx,
			       smb_krb5_context,
			       k);
		talloc_free(smb_krb5_context);
		*r->out.info = info;
		return NT_STATUS_OK;
	}
	default:
		talloc_free(info);
		*r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}
}

/*
  lsa_SetDomInfoPolicy
*/
static NTSTATUS dcesrv_lsa_SetDomainInformationPolicy(struct dcesrv_call_state *dce_call,
					      TALLOC_CTX *mem_ctx,
					      struct lsa_SetDomainInformationPolicy *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_TestCall
*/
static NTSTATUS dcesrv_lsa_TestCall(struct dcesrv_call_state *dce_call,
			     TALLOC_CTX *mem_ctx,
			     struct lsa_TestCall *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_CREDRWRITE
*/
static NTSTATUS dcesrv_lsa_CREDRWRITE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRWRITE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRREAD
*/
static NTSTATUS dcesrv_lsa_CREDRREAD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRREAD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRENUMERATE
*/
static NTSTATUS dcesrv_lsa_CREDRENUMERATE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRENUMERATE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRWRITEDOMAINCREDENTIALS
*/
static NTSTATUS dcesrv_lsa_CREDRWRITEDOMAINCREDENTIALS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRWRITEDOMAINCREDENTIALS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRREADDOMAINCREDENTIALS
*/
static NTSTATUS dcesrv_lsa_CREDRREADDOMAINCREDENTIALS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRREADDOMAINCREDENTIALS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRDELETE
*/
static NTSTATUS dcesrv_lsa_CREDRDELETE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRDELETE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRGETTARGETINFO
*/
static NTSTATUS dcesrv_lsa_CREDRGETTARGETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRGETTARGETINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRPROFILELOADED
*/
static NTSTATUS dcesrv_lsa_CREDRPROFILELOADED(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRPROFILELOADED *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_CREDRGETSESSIONTYPES
*/
static NTSTATUS dcesrv_lsa_CREDRGETSESSIONTYPES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRGETSESSIONTYPES *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_LSARREGISTERAUDITEVENT
*/
static NTSTATUS dcesrv_lsa_LSARREGISTERAUDITEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARREGISTERAUDITEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_LSARGENAUDITEVENT
*/
static NTSTATUS dcesrv_lsa_LSARGENAUDITEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARGENAUDITEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_LSARUNREGISTERAUDITEVENT
*/
static NTSTATUS dcesrv_lsa_LSARUNREGISTERAUDITEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARUNREGISTERAUDITEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_lsaRQueryForestTrustInformation
*/
static NTSTATUS dcesrv_lsa_lsaRQueryForestTrustInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_lsaRQueryForestTrustInformation *r)
{
	struct dcesrv_handle *h = NULL;
	struct lsa_policy_state *p_state = NULL;
	int forest_level = DS_DOMAIN_FUNCTION_2000;
	const char * const trust_attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAttributes",
		"trustDirection",
		"trustType",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ldb_message *trust_tdo_msg = NULL;
	struct lsa_TrustDomainInfoInfoEx *trust_tdo = NULL;
	struct ForestTrustInfo *trust_fti = NULL;
	struct lsa_ForestTrustInformation *trust_lfti = NULL;
	NTSTATUS status;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	p_state = h->data;

	if (strcmp(p_state->domain_dns, p_state->forest_dns)) {
		return NT_STATUS_INVALID_DOMAIN_STATE;
	}

	forest_level = dsdb_forest_functional_level(p_state->sam_ldb);
	if (forest_level < DS_DOMAIN_FUNCTION_2003) {
		return NT_STATUS_INVALID_DOMAIN_STATE;
	}

	if (r->in.trusted_domain_name->string == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	status = dsdb_trust_search_tdo(p_state->sam_ldb,
				       r->in.trusted_domain_name->string,
				       r->in.trusted_domain_name->string,
				       trust_attrs, mem_ctx, &trust_tdo_msg);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dsdb_trust_parse_tdo_info(mem_ctx, trust_tdo_msg, &trust_tdo);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!(trust_tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.highest_record_type >= LSA_FOREST_TRUST_RECORD_TYPE_LAST) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dsdb_trust_parse_forest_info(mem_ctx,
					      trust_tdo_msg,
					      &trust_fti);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dsdb_trust_forest_info_to_lsa(mem_ctx, trust_fti,
					       &trust_lfti);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*r->out.forest_trust_info = trust_lfti;
	return NT_STATUS_OK;
}

/*
  lsa_lsaRSetForestTrustInformation
*/
static NTSTATUS dcesrv_lsa_lsaRSetForestTrustInformation(struct dcesrv_call_state *dce_call,
							 TALLOC_CTX *mem_ctx,
							 struct lsa_lsaRSetForestTrustInformation *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *p_state;
	const char * const trust_attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAttributes",
		"trustDirection",
		"trustType",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ldb_message *trust_tdo_msg = NULL;
	struct lsa_TrustDomainInfoInfoEx *trust_tdo = NULL;
	struct lsa_ForestTrustInformation *step1_lfti = NULL;
	struct lsa_ForestTrustInformation *step2_lfti = NULL;
	struct ForestTrustInfo *trust_fti = NULL;
	struct ldb_result *trusts_res = NULL;
	unsigned int i;
	struct lsa_TrustDomainInfoInfoEx *xref_tdo = NULL;
	struct lsa_ForestTrustInformation *xref_lfti = NULL;
	struct lsa_ForestTrustCollisionInfo *c_info = NULL;
	DATA_BLOB ft_blob = {};
	struct ldb_message *msg = NULL;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	int ret;
	bool in_transaction = false;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	p_state = h->data;

	if (strcmp(p_state->domain_dns, p_state->forest_dns)) {
		return NT_STATUS_INVALID_DOMAIN_STATE;
	}

	if (r->in.check_only == 0) {
		ret = ldb_transaction_start(p_state->sam_ldb);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		in_transaction = true;
	}

	/*
	 * abort if we are not a PDC
	 *
	 * In future we should use a function like IsEffectiveRoleOwner()
	 */
	if (!samdb_is_pdc(p_state->sam_ldb)) {
		status = NT_STATUS_INVALID_DOMAIN_ROLE;
		goto done;
	}

	if (r->in.trusted_domain_name->string == NULL) {
		status = NT_STATUS_NO_SUCH_DOMAIN;
		goto done;
	}

	status = dsdb_trust_search_tdo(p_state->sam_ldb,
				       r->in.trusted_domain_name->string,
				       r->in.trusted_domain_name->string,
				       trust_attrs, mem_ctx, &trust_tdo_msg);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		status = NT_STATUS_NO_SUCH_DOMAIN;
		goto done;
	}
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dsdb_trust_parse_tdo_info(mem_ctx, trust_tdo_msg, &trust_tdo);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (!(trust_tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (r->in.highest_record_type >= LSA_FOREST_TRUST_RECORD_TYPE_LAST) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/*
	 * verify and normalize the given forest trust info.
	 *
	 * Step1: doesn't reorder yet, so step1_lfti might contain
	 * NULL entries. This means dsdb_trust_verify_forest_info()
	 * can generate collision entries with the callers index.
	 */
	status = dsdb_trust_normalize_forest_info_step1(mem_ctx,
							r->in.forest_trust_info,
							&step1_lfti);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	c_info = talloc_zero(r->out.collision_info,
			     struct lsa_ForestTrustCollisionInfo);
	if (c_info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/*
	 * First check our own forest, then other domains/forests
	 */

	status = dsdb_trust_xref_tdo_info(mem_ctx, p_state->sam_ldb,
					  &xref_tdo);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	status = dsdb_trust_xref_forest_info(mem_ctx, p_state->sam_ldb,
					     &xref_lfti);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/*
	 * The documentation proposed to generate
	 * LSA_FOREST_TRUST_COLLISION_XREF collisions.
	 * But Windows always uses LSA_FOREST_TRUST_COLLISION_TDO.
	 */
	status = dsdb_trust_verify_forest_info(xref_tdo, xref_lfti,
					       LSA_FOREST_TRUST_COLLISION_TDO,
					       c_info, step1_lfti);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* fetch all other trusted domain objects */
	status = dsdb_trust_search_tdos(p_state->sam_ldb,
					trust_tdo->domain_name.string,
					trust_attrs,
					mem_ctx, &trusts_res);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/*
	 * now check against the other domains.
	 * and generate LSA_FOREST_TRUST_COLLISION_TDO collisions.
	 */
	for (i = 0; i < trusts_res->count; i++) {
		struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
		struct ForestTrustInfo *fti = NULL;
		struct lsa_ForestTrustInformation *lfti = NULL;

		status = dsdb_trust_parse_tdo_info(mem_ctx,
						   trusts_res->msgs[i],
						   &tdo);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		status = dsdb_trust_parse_forest_info(tdo,
						      trusts_res->msgs[i],
						      &fti);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			continue;
		}
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		status = dsdb_trust_forest_info_to_lsa(tdo, fti, &lfti);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		status = dsdb_trust_verify_forest_info(tdo, lfti,
						LSA_FOREST_TRUST_COLLISION_TDO,
						c_info, step1_lfti);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		TALLOC_FREE(tdo);
	}

	if (r->in.check_only != 0) {
		status = NT_STATUS_OK;
		goto done;
	}

	/*
	 * not just a check, write info back
	 */

	/*
	 * normalize the given forest trust info.
	 *
	 * Step2: adds TOP_LEVEL_NAME[_EX] in reverse order,
	 * followed by DOMAIN_INFO in reverse order. It also removes
	 * possible NULL entries from Step1.
	 */
	status = dsdb_trust_normalize_forest_info_step2(mem_ctx, step1_lfti,
							&step2_lfti);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dsdb_trust_forest_info_from_lsa(mem_ctx, step2_lfti,
						 &trust_fti);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	ndr_err = ndr_push_struct_blob(&ft_blob, mem_ctx, trust_fti,
				       (ndr_push_flags_fn_t)ndr_push_ForestTrustInfo);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	msg->dn = ldb_dn_copy(mem_ctx, trust_tdo_msg->dn);
	if (!msg->dn) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ret = ldb_msg_add_empty(msg, "msDS-TrustForestTrustInfo",
				LDB_FLAG_MOD_REPLACE, NULL);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	ret = ldb_msg_add_value(msg, "msDS-TrustForestTrustInfo",
				&ft_blob, NULL);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ret = ldb_modify(p_state->sam_ldb, msg);
	if (ret != LDB_SUCCESS) {
		status = dsdb_ldb_err_to_ntstatus(ret);

		DEBUG(0, ("Failed to store Forest Trust Info: %s\n",
			  ldb_errstring(p_state->sam_ldb)));

		goto done;
	}

	/* ok, all fine, commit transaction and return */
	in_transaction = false;
	ret = ldb_transaction_commit(p_state->sam_ldb);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}

	status = NT_STATUS_OK;

done:
	if (NT_STATUS_IS_OK(status) && c_info->count != 0) {
		*r->out.collision_info = c_info;
	}

	if (in_transaction) {
		ldb_transaction_cancel(p_state->sam_ldb);
	}

	return status;
}

/*
  lsa_CREDRRENAME
*/
static NTSTATUS dcesrv_lsa_CREDRRENAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRRENAME *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/*
  lsa_LSAROPENPOLICYSCE
*/
static NTSTATUS dcesrv_lsa_LSAROPENPOLICYSCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSAROPENPOLICYSCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_LSARADTREGISTERSECURITYEVENTSOURCE
*/
static NTSTATUS dcesrv_lsa_LSARADTREGISTERSECURITYEVENTSOURCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARADTREGISTERSECURITYEVENTSOURCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE
*/
static NTSTATUS dcesrv_lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  lsa_LSARADTREPORTSECURITYEVENT
*/
static NTSTATUS dcesrv_lsa_LSARADTREPORTSECURITYEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARADTREPORTSECURITYEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_lsa_s.c"



/*****************************************
NOTE! The remaining calls below were
removed in w2k3, so the DCESRV_FAULT()
replies are the correct implementation. Do
not try and fill these in with anything else
******************************************/

/*
  dssetup_DsRoleDnsNameToFlatName
*/
static WERROR dcesrv_dssetup_DsRoleDnsNameToFlatName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct dssetup_DsRoleDnsNameToFlatName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  dssetup_DsRoleDcAsDc
*/
static WERROR dcesrv_dssetup_DsRoleDcAsDc(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct dssetup_DsRoleDcAsDc *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  dssetup_DsRoleDcAsReplica
*/
static WERROR dcesrv_dssetup_DsRoleDcAsReplica(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct dssetup_DsRoleDcAsReplica *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  dssetup_DsRoleDemoteDc
*/
static WERROR dcesrv_dssetup_DsRoleDemoteDc(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct dssetup_DsRoleDemoteDc *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  dssetup_DsRoleGetDcOperationProgress
*/
static WERROR dcesrv_dssetup_DsRoleGetDcOperationProgress(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					     struct dssetup_DsRoleGetDcOperationProgress *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleGetDcOperationResults 
*/
static WERROR dcesrv_dssetup_DsRoleGetDcOperationResults(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct dssetup_DsRoleGetDcOperationResults *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleCancel 
*/
static WERROR dcesrv_dssetup_DsRoleCancel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct dssetup_DsRoleCancel *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  dssetup_DsRoleServerSaveStateForUpgrade
*/
static WERROR dcesrv_dssetup_DsRoleServerSaveStateForUpgrade(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct dssetup_DsRoleServerSaveStateForUpgrade *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  dssetup_DsRoleUpgradeDownlevelServer
*/
static WERROR dcesrv_dssetup_DsRoleUpgradeDownlevelServer(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					     struct dssetup_DsRoleUpgradeDownlevelServer *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  dssetup_DsRoleAbortDownlevelServerUpgrade
*/
static WERROR dcesrv_dssetup_DsRoleAbortDownlevelServerUpgrade(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						  struct dssetup_DsRoleAbortDownlevelServerUpgrade *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_dssetup_s.c"

NTSTATUS dcerpc_server_lsa_init(void)
{
	NTSTATUS ret;

	ret = dcerpc_server_dssetup_init();
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}
	ret = dcerpc_server_lsarpc_init();
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}
	return ret;
}
