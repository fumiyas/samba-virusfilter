/*
   Unix SMB/CIFS implementation.

   Wrapper around winbindd_ads.c to centralize retry logic.
   Copyright (C) Christof Schmitt 2016

   Based on winbindd_reconnect.c
   Copyright (C) Volker Lendecke 2005

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

#ifdef HAVE_ADS

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

extern struct winbindd_methods ads_methods;

/* List all users */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32_t *num_entries,
				struct wbint_userinfo **info)
{
	NTSTATUS result;

	result = ads_methods.query_user_list(domain, mem_ctx,
					     num_entries, info);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.query_user_list(domain, mem_ctx,
						     num_entries, info);
	}

	return result;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32_t *num_entries,
				struct wb_acct_info **info)
{
	NTSTATUS result;

	result = ads_methods.enum_dom_groups(domain, mem_ctx,
					     num_entries, info);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.enum_dom_groups(domain, mem_ctx,
						     num_entries, info);
	}

	return result;
}

/* List all domain groups */
static NTSTATUS enum_local_groups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  uint32_t *num_entries,
				  struct wb_acct_info **info)
{
	NTSTATUS result;

	result = ads_methods.enum_local_groups(domain, mem_ctx,
					       num_entries, info);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.enum_local_groups(domain, mem_ctx,
						       num_entries, info);
	}

	return result;
}

/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const char *domain_name,
			    const char *name,
			    uint32_t flags,
			    struct dom_sid *sid,
			    enum lsa_SidType *type)
{
	NTSTATUS result;

	result = ads_methods.name_to_sid(domain, mem_ctx, domain_name, name,
					 flags, sid, type);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.name_to_sid(domain, mem_ctx,
						 domain_name, name, flags,
						 sid, type);
	}

	return result;
}

/*
  convert a domain SID to a user or group name
*/
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const struct dom_sid *sid,
			    char **domain_name,
			    char **name,
			    enum lsa_SidType *type)
{
	NTSTATUS result;

	result = ads_methods.sid_to_name(domain, mem_ctx, sid,
					 domain_name, name, type);

	if (reconnect_need_retry(result, domain))
		result = ads_methods.sid_to_name(domain, mem_ctx, sid,
						 domain_name, name, type);

	return result;
}

static NTSTATUS rids_to_names(struct winbindd_domain *domain,
			      TALLOC_CTX *mem_ctx,
			      const struct dom_sid *sid,
			      uint32_t *rids,
			      size_t num_rids,
			      char **domain_name,
			      char ***names,
			      enum lsa_SidType **types)
{
	NTSTATUS result;

	result = ads_methods.rids_to_names(domain, mem_ctx, sid,
					   rids, num_rids,
					   domain_name, names, types);
	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.rids_to_names(domain, mem_ctx, sid,
						   rids, num_rids, domain_name,
						   names, types);
	}

	return result;
}

/* Lookup user information from a rid or username. */
static NTSTATUS query_user(struct winbindd_domain *domain,
			   TALLOC_CTX *mem_ctx,
			   const struct dom_sid *user_sid,
			   struct wbint_userinfo *user_info)
{
	NTSTATUS result;

	result = ads_methods.query_user(domain, mem_ctx, user_sid, user_info);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.query_user(domain, mem_ctx, user_sid,
						user_info);
	}

	return result;
}

/* Lookup groups a user is a member of.  I wish Unix had a call like this! */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const struct dom_sid *user_sid,
				  uint32_t *num_groups,
				  struct dom_sid **user_gids)
{
	NTSTATUS result;

	result = ads_methods.lookup_usergroups(domain, mem_ctx, user_sid,
					       num_groups, user_gids);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.lookup_usergroups(domain, mem_ctx,
						       user_sid, num_groups,
						       user_gids);
	}

	return result;
}

static NTSTATUS lookup_useraliases(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   uint32_t num_sids,
				   const struct dom_sid *sids,
				   uint32_t *num_aliases, uint32_t **alias_rids)
{
	NTSTATUS result;

	result = ads_methods.lookup_useraliases(domain, mem_ctx, num_sids, sids,
						num_aliases, alias_rids);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.lookup_useraliases(domain, mem_ctx,
							num_sids, sids,
							num_aliases,
							alias_rids);
	}

	return result;
}

/* Lookup group membership given a rid.   */
static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const struct dom_sid *group_sid,
				enum lsa_SidType type,
				uint32_t *num_names,
				struct dom_sid **sid_mem, char ***names,
				uint32_t **name_types)
{
	NTSTATUS result;

	result = ads_methods.lookup_groupmem(domain, mem_ctx, group_sid, type,
					     num_names, sid_mem, names,
					     name_types);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.lookup_groupmem(domain, mem_ctx, group_sid,
						     type, num_names, sid_mem,
						     names, name_types);
	}

	return result;
}

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32_t *seq)
{
	NTSTATUS result;

	result = ads_methods.sequence_number(domain, seq);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.sequence_number(domain, seq);
	}

	return result;
}

/* find the lockout policy of a domain */
static NTSTATUS lockout_policy(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       struct samr_DomInfo12 *policy)
{
	NTSTATUS result;

	result = ads_methods.lockout_policy(domain, mem_ctx, policy);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.lockout_policy(domain, mem_ctx, policy);
	}

	return result;
}

/* find the password policy of a domain */
static NTSTATUS password_policy(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				struct samr_DomInfo1 *policy)
{
	NTSTATUS result;

	result = ads_methods.password_policy(domain, mem_ctx, policy);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.password_policy(domain, mem_ctx, policy);
	}

	return result;
}

/* get a list of trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				struct netr_DomainTrustList *trusts)
{
	NTSTATUS result;

	result = ads_methods.trusted_domains(domain, mem_ctx, trusts);

	if (reconnect_need_retry(result, domain)) {
		result = ads_methods.trusted_domains(domain, mem_ctx, trusts);
	}

	return result;
}

/* the rpc backend methods are exposed via this structure */
struct winbindd_methods reconnect_ads_methods = {
	true,
	query_user_list,
	enum_dom_groups,
	enum_local_groups,
	name_to_sid,
	sid_to_name,
	rids_to_names,
	query_user,
	lookup_usergroups,
	lookup_useraliases,
	lookup_groupmem,
	sequence_number,
	lockout_policy,
	password_policy,
	trusted_domains,
};

#endif
