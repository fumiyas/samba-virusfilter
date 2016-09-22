/*
   Unix SMB/CIFS implementation.
   Check access based on valid users, read list and friends
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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/security/security.h"
#include "passdb/lookup_sid.h"
#include "auth.h"

/*
 * No prefix means direct username
 * @name means netgroup first, then unix group
 * &name means netgroup
 * +name means unix group
 * + and & may be combined
 */

static bool do_group_checks(const char **name, const char **pattern)
{
	if ((*name)[0] == '@') {
		*pattern = "&+";
		*name += 1;
		return True;
	}

	if (((*name)[0] == '+') && ((*name)[1] == '&')) {
		*pattern = "+&";
		*name += 2;
		return True;
	}

	if ((*name)[0] == '+') {
		*pattern = "+";
		*name += 1;
		return True;
	}

	if (((*name)[0] == '&') && ((*name)[1] == '+')) {
		*pattern = "&+";
		*name += 2;
		return True;
	}

	if ((*name)[0] == '&') {
		*pattern = "&";
		*name += 1;
		return True;
	}

	return False;
}

static bool token_contains_name(TALLOC_CTX *mem_ctx,
				const char *username,
				const char *domain,
				const char *sharename,
				const struct security_token *token,
				const char *name)
{
	const char *prefix;
	struct dom_sid sid;
	enum lsa_SidType type;

	if (username != NULL) {
		name = talloc_sub_basic(mem_ctx, username, domain, name);
	}
	if (sharename != NULL) {
		name = talloc_string_sub(mem_ctx, name, "%S", sharename);
	}

	if (name == NULL) {
		/* This is too security sensitive, better panic than return a
		 * result that might be interpreted in a wrong way. */
		smb_panic("substitutions failed");
	}

	if ( string_to_sid( &sid, name ) ) {
		DEBUG(5,("token_contains_name: Checking for SID [%s] in token\n", name));
		return nt_token_check_sid( &sid, token );
	}

	if (!do_group_checks(&name, &prefix)) {
		if (!lookup_name_smbconf(mem_ctx, name, LOOKUP_NAME_ALL,
				 NULL, NULL, &sid, &type)) {
			DEBUG(5, ("lookup_name %s failed\n", name));
			return False;
		}
		if (type != SID_NAME_USER) {
			DEBUG(5, ("%s is a %s, expected a user\n",
				  name, sid_type_lookup(type)));
			return False;
		}
		return nt_token_check_sid(&sid, token);
	}

	for (/* initialized above */ ; *prefix != '\0'; prefix++) {
		if (*prefix == '+') {
			if (!lookup_name_smbconf(mem_ctx, name,
					 LOOKUP_NAME_ALL|LOOKUP_NAME_GROUP,
					 NULL, NULL, &sid, &type)) {
				DEBUG(5, ("lookup_name %s failed\n", name));
				return False;
			}
			if ((type != SID_NAME_DOM_GRP) &&
			    (type != SID_NAME_ALIAS) &&
			    (type != SID_NAME_WKN_GRP)) {
				DEBUG(5, ("%s is a %s, expected a group\n",
					  name, sid_type_lookup(type)));
				return False;
			}
			if (nt_token_check_sid(&sid, token)) {
				return True;
			}
			continue;
		}
		if (*prefix == '&') {
			if (username) {
				if (user_in_netgroup(mem_ctx, username, name)) {
					return True;
				}
			}
			continue;
		}
		smb_panic("got invalid prefix from do_groups_check");
	}
	return False;
}

/*
 * Check whether a user is contained in the list provided.
 *
 * Please note that the user name and share names passed in here mainly for
 * the substitution routines that expand the parameter values, the decision
 * whether a user is in the list is done after a lookup_name on the expanded
 * parameter value, solely based on comparing the SIDs in token.
 *
 * The other use is the netgroup check when using @group or &group.
 */

bool token_contains_name_in_list(const char *username,
				 const char *domain,
				 const char *sharename,
				 const struct security_token *token,
				 const char **list)
{
	if (list == NULL) {
		return False;
	}
	while (*list != NULL) {
		TALLOC_CTX *frame = talloc_stackframe();
		bool ret;

		ret = token_contains_name(frame, username, domain, sharename,
					  token, *list);
		TALLOC_FREE(frame);
		if (ret) {
			return true;
		}
		list += 1;
	}
	return False;
}

/*
 * Check whether the user described by "token" has access to share snum.
 *
 * This looks at "invalid users" and "valid users".
 *
 * Please note that the user name and share names passed in here mainly for
 * the substitution routines that expand the parameter values, the decision
 * whether a user is in the list is done after a lookup_name on the expanded
 * parameter value, solely based on comparing the SIDs in token.
 *
 * The other use is the netgroup check when using @group or &group.
 */

bool user_ok_token(const char *username, const char *domain,
		   const struct security_token *token, int snum)
{
	if (lp_invalid_users(snum) != NULL) {
		if (token_contains_name_in_list(username, domain,
						lp_servicename(talloc_tos(), snum),
						token,
						lp_invalid_users(snum))) {
			DEBUG(10, ("User %s in 'invalid users'\n", username));
			return False;
		}
	}

	if (lp_valid_users(snum) != NULL) {
		if (!token_contains_name_in_list(username, domain,
						 lp_servicename(talloc_tos(), snum),
						 token,
						 lp_valid_users(snum))) {
			DEBUG(10, ("User %s not in 'valid users'\n",
				   username));
			return False;
		}
	}

	DEBUG(10, ("user_ok_token: share %s is ok for unix user %s\n",
		   lp_servicename(talloc_tos(), snum), username));

	return True;
}

/*
 * Check whether the user described by "token" is restricted to read-only
 * access on share snum.
 *
 * This looks at "read list", "write list" and "read only".
 *
 * Please note that the user name and share names passed in here mainly for
 * the substitution routines that expand the parameter values, the decision
 * whether a user is in the list is done after a lookup_name on the expanded
 * parameter value, solely based on comparing the SIDs in token.
 *
 * The other use is the netgroup check when using @group or &group.
 */

bool is_share_read_only_for_token(const char *username,
				  const char *domain,
				  const struct security_token *token,
				  connection_struct *conn)
{
	int snum = SNUM(conn);
	bool result = conn->read_only;

	if (lp_read_list(snum) != NULL) {
		if (token_contains_name_in_list(username, domain,
						lp_servicename(talloc_tos(), snum),
						token,
						lp_read_list(snum))) {
			result = True;
		}
	}

	if (lp_write_list(snum) != NULL) {
		if (token_contains_name_in_list(username, domain,
						lp_servicename(talloc_tos(), snum),
						token,
						lp_write_list(snum))) {
			result = False;
		}
	}

	DEBUG(10,("is_share_read_only_for_user: share %s is %s for unix user "
		  "%s\n", lp_servicename(talloc_tos(), snum),
		  result ? "read-only" : "read-write", username));

	return result;
}
