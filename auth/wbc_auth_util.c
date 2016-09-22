/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Volker Lendecke 2010

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
#include "libcli/security/security.h"
#include "librpc/gen_ndr/netlogon.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "librpc/gen_ndr/auth.h"
#include "auth/auth_sam_reply.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

static NTSTATUS wbcsids_to_samr_RidWithAttributeArray(
				TALLOC_CTX *mem_ctx,
				struct samr_RidWithAttributeArray *groups,
				const struct dom_sid *domain_sid,
				const struct wbcSidWithAttr *sids,
				size_t num_sids)
{
	unsigned int i, j = 0;
	bool ok;

	groups->rids = talloc_array(mem_ctx,
				    struct samr_RidWithAttribute, num_sids);
	if (!groups->rids) {
		return NT_STATUS_NO_MEMORY;
	}

	/* a wbcDomainSid is the same as a dom_sid */
	for (i = 0; i < num_sids; i++) {
		ok = sid_peek_check_rid(domain_sid,
					(const struct dom_sid *)&sids[i].sid,
					&groups->rids[j].rid);
		if (!ok) continue;

		groups->rids[j].attributes = SE_GROUP_MANDATORY |
					     SE_GROUP_ENABLED_BY_DEFAULT |
					     SE_GROUP_ENABLED;
		j++;
	}

	groups->count = j;
	return NT_STATUS_OK;
}

static NTSTATUS wbcsids_to_netr_SidAttrArray(
				const struct dom_sid *domain_sid,
				const struct wbcSidWithAttr *sids,
				size_t num_sids,
				TALLOC_CTX *mem_ctx,
				struct netr_SidAttr **_info3_sids,
				uint32_t *info3_num_sids)
{
	unsigned int i, j = 0;
	struct netr_SidAttr *info3_sids;

	info3_sids = talloc_array(mem_ctx, struct netr_SidAttr, num_sids);
	if (info3_sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* a wbcDomainSid is the same as a dom_sid */
	for (i = 0; i < num_sids; i++) {
		const struct dom_sid *sid;

		sid = (const struct dom_sid *)&sids[i].sid;

		if (dom_sid_in_domain(domain_sid, sid)) {
			continue;
		}

		info3_sids[j].sid = dom_sid_dup(info3_sids, sid);
		if (info3_sids[j].sid == NULL) {
			talloc_free(info3_sids);
			return NT_STATUS_NO_MEMORY;
		}
		info3_sids[j].attributes = SE_GROUP_MANDATORY |
					   SE_GROUP_ENABLED_BY_DEFAULT |
					   SE_GROUP_ENABLED;
		j++;
	}

	*info3_num_sids = j;
	*_info3_sids = info3_sids;
	return NT_STATUS_OK;
}

#undef RET_NOMEM

#define RET_NOMEM(ptr) do { \
	if (!ptr) { \
		TALLOC_FREE(info6); \
		return NULL; \
	} } while(0)

struct netr_SamInfo6 *wbcAuthUserInfo_to_netr_SamInfo6(TALLOC_CTX *mem_ctx,
					const struct wbcAuthUserInfo *info)
{
	struct netr_SamInfo6 *info6;
	struct dom_sid user_sid;
	struct dom_sid group_sid;
	struct dom_sid domain_sid;
	NTSTATUS status;
	bool ok;

	memcpy(&user_sid, &info->sids[0].sid, sizeof(user_sid));
	memcpy(&group_sid, &info->sids[1].sid, sizeof(group_sid));

	info6 = talloc_zero(mem_ctx, struct netr_SamInfo6);
	if (!info6) return NULL;

	unix_to_nt_time(&info6->base.logon_time, info->logon_time);
	unix_to_nt_time(&info6->base.logoff_time, info->logoff_time);
	unix_to_nt_time(&info6->base.kickoff_time, info->kickoff_time);
	unix_to_nt_time(&info6->base.last_password_change, info->pass_last_set_time);
	unix_to_nt_time(&info6->base.allow_password_change,
			info->pass_can_change_time);
	unix_to_nt_time(&info6->base.force_password_change,
			info->pass_must_change_time);

	if (info->account_name) {
		info6->base.account_name.string	=
				talloc_strdup(info6, info->account_name);
		RET_NOMEM(info6->base.account_name.string);
	}
	if (info->user_principal) {
		info6->principal_name.string	=
				talloc_strdup(info6, info->user_principal);
		RET_NOMEM(info6->principal_name.string);
	}
	if (info->full_name) {
		info6->base.full_name.string =
				talloc_strdup(info6, info->full_name);
		RET_NOMEM(info6->base.full_name.string);
	}
	if (info->domain_name) {
		info6->base.logon_domain.string	=
				talloc_strdup(info6, info->domain_name);
		RET_NOMEM(info6->base.logon_domain.string);
	}
	if (info->dns_domain_name) {
		info6->dns_domainname.string	=
				talloc_strdup(info6, info->dns_domain_name);
		RET_NOMEM(info6->dns_domainname.string);
	}
	if (info->logon_script) {
		info6->base.logon_script.string =
				talloc_strdup(info6, info->logon_script);
		RET_NOMEM(info6->base.logon_script.string);
	}
	if (info->profile_path) {
		info6->base.profile_path.string	=
				talloc_strdup(info6, info->profile_path);
		RET_NOMEM(info6->base.profile_path.string);
	}
	if (info->home_directory) {
		info6->base.home_directory.string =
				talloc_strdup(info6, info->home_directory);
		RET_NOMEM(info6->base.home_directory.string);
	}
	if (info->home_drive) {
		info6->base.home_drive.string =
				talloc_strdup(info6, info->home_drive);
		RET_NOMEM(info6->base.home_drive.string);
	}

	info6->base.logon_count	= info->logon_count;
	info6->base.bad_password_count = info->bad_password_count;

	sid_copy(&domain_sid, &user_sid);
	sid_split_rid(&domain_sid, &info6->base.rid);

	ok = sid_peek_check_rid(&domain_sid, &group_sid,
				&info6->base.primary_gid);
	if (!ok) {
		DEBUG(1, ("The primary group sid domain does not"
			  "match user sid domain for user: %s\n",
			  info->account_name));
		TALLOC_FREE(info6);
		return NULL;
	}

	status = wbcsids_to_samr_RidWithAttributeArray(info6,
						       &info6->base.groups,
						       &domain_sid,
						       &info->sids[1],
						       info->num_sids - 1);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info6);
		return NULL;
	}

	status = wbcsids_to_netr_SidAttrArray(&domain_sid,
					      &info->sids[1],
					      info->num_sids - 1,
					      info6,
					      &info6->sids,
					      &info6->sidcount);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info6);
		return NULL;
	}

	info6->base.user_flags = info->user_flags;
	memcpy(info6->base.key.key, info->user_session_key, 16);

	if (info->logon_server) {
		info6->base.logon_server.string =
				talloc_strdup(info6, info->logon_server);
		RET_NOMEM(info6->base.logon_server.string);
	}
	if (info->domain_name) {
		info6->base.logon_domain.string =
				talloc_strdup(info6, info->domain_name);
		RET_NOMEM(info6->base.logon_domain.string);
	}

	info6->base.domain_sid = dom_sid_dup(info6, &domain_sid);
	RET_NOMEM(info6->base.domain_sid);

	memcpy(info6->base.LMSessKey.key, info->lm_session_key, 8);
	info6->base.acct_flags = info->acct_flags;

	return info6;
}
