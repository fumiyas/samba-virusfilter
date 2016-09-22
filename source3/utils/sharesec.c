/*
 *  Unix SMB/Netbios implementation.
 *  Utility for managing share permissions
 *
 *  Copyright (C) Tim Potter                    2000
 *  Copyright (C) Jeremy Allison                2000
 *  Copyright (C) Jelmer Vernooij               2003
 *  Copyright (C) Gerald (Jerry) Carter         2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

struct cli_state;

#include "includes.h"
#include "popt_common.h"
#include "../libcli/security/security.h"
#include "passdb/machine_sid.h"
#include "util_sd.h"

static TALLOC_CTX *ctx;

enum acl_mode { SMB_ACL_DELETE,
	        SMB_ACL_MODIFY,
	        SMB_ACL_ADD,
	        SMB_ACL_SET,
		SMB_SD_DELETE,
		SMB_SD_SETSDDL,
		SMB_SD_VIEWSDDL,
	        SMB_ACL_VIEW,
		SMB_ACL_VIEW_ALL };

/********************************************************************
********************************************************************/

static struct security_descriptor* parse_acl_string(TALLOC_CTX *mem_ctx, const char *szACL, size_t *sd_size )
{
	struct security_descriptor *sd = NULL;
	struct security_ace *ace;
	struct security_acl *theacl;
	int num_ace;
	const char *pacl;
	int i;

	if ( !szACL )
		return NULL;

	pacl = szACL;
	num_ace = count_chars( pacl, ',' ) + 1;

	if ( !(ace = talloc_zero_array( mem_ctx, struct security_ace, num_ace )) )
		return NULL;

	for ( i=0; i<num_ace; i++ ) {
		char *end_acl = strchr_m( pacl, ',' );
		fstring acl_string;

		strncpy( acl_string, pacl, MIN( PTR_DIFF( end_acl, pacl ), sizeof(fstring)-1) );
		acl_string[MIN( PTR_DIFF( end_acl, pacl ), sizeof(fstring)-1)] = '\0';

		if ( !parse_ace(NULL, &ace[i], acl_string ) )
			return NULL;

		pacl = end_acl;
		pacl++;
	}

	if ( !(theacl = make_sec_acl( mem_ctx, NT4_ACL_REVISION, num_ace, ace )) )
		return NULL;

	sd = make_sec_desc( mem_ctx, SD_REVISION, SEC_DESC_SELF_RELATIVE,
		NULL, NULL, NULL, theacl, sd_size);

	return sd;
}

/* add an ACE to a list of ACEs in a struct security_acl */
static bool add_ace(TALLOC_CTX *mem_ctx, struct security_acl **the_acl, struct security_ace *ace)
{
	struct security_acl *new_ace;
	struct security_ace *aces;
	if (! *the_acl) {
		return (((*the_acl) = make_sec_acl(mem_ctx, 3, 1, ace)) != NULL);
	}

	if (!(aces = SMB_CALLOC_ARRAY(struct security_ace, 1+(*the_acl)->num_aces))) {
		return False;
	}
	memcpy(aces, (*the_acl)->aces, (*the_acl)->num_aces * sizeof(struct
	security_ace));
	memcpy(aces+(*the_acl)->num_aces, ace, sizeof(struct security_ace));
	new_ace = make_sec_acl(mem_ctx,(*the_acl)->revision,1+(*the_acl)->num_aces, aces);
	SAFE_FREE(aces);
	(*the_acl) = new_ace;
	return True;
}

/* The MSDN is contradictory over the ordering of ACE entries in an ACL.
   However NT4 gives a "The information may have been modified by a
   computer running Windows NT 5.0" if denied ACEs do not appear before
   allowed ACEs. */

static int ace_compare(struct security_ace *ace1, struct security_ace *ace2)
{
	if (security_ace_equal(ace1, ace2))
		return 0;

	if (ace1->type != ace2->type)
		return ace2->type - ace1->type;

	if (dom_sid_compare(&ace1->trustee, &ace2->trustee))
		return dom_sid_compare(&ace1->trustee, &ace2->trustee);

	if (ace1->flags != ace2->flags)
		return ace1->flags - ace2->flags;

	if (ace1->access_mask != ace2->access_mask)
		return ace1->access_mask - ace2->access_mask;

	if (ace1->size != ace2->size)
		return ace1->size - ace2->size;

	return memcmp(ace1, ace2, sizeof(struct security_ace));
}

static void sort_acl(struct security_acl *the_acl)
{
	uint32_t i;
	if (!the_acl) return;

	TYPESAFE_QSORT(the_acl->aces, the_acl->num_aces, ace_compare);

	for (i=1;i<the_acl->num_aces;) {
		if (security_ace_equal(&the_acl->aces[i-1],
				       &the_acl->aces[i])) {
			int j;
			for (j=i; j<the_acl->num_aces-1; j++) {
				the_acl->aces[j] = the_acl->aces[j+1];
			}
			the_acl->num_aces--;
		} else {
			i++;
		}
	}
}


static int change_share_sec(TALLOC_CTX *mem_ctx, const char *sharename, char *the_acl, enum acl_mode mode)
{
	struct security_descriptor *sd = NULL;
	struct security_descriptor *old = NULL;
	size_t sd_size = 0;
	uint32_t i, j;

	if (mode != SMB_ACL_SET && mode != SMB_SD_DELETE) {
	    if (!(old = get_share_security( mem_ctx, sharename, &sd_size )) ) {
		fprintf(stderr, "Unable to retrieve permissions for share "
			"[%s]\n", sharename);
		return -1;
	    }
	}

	if ( (mode != SMB_ACL_VIEW && mode != SMB_SD_DELETE) &&
	    !(sd = parse_acl_string(mem_ctx, the_acl, &sd_size )) ) {
		fprintf( stderr, "Failed to parse acl\n");
		return -1;
	}

	switch (mode) {
	case SMB_ACL_VIEW_ALL:
		/* should not happen */
		return 0;
	case SMB_ACL_VIEW:
		sec_desc_print(NULL, stdout, old, false);
		return 0;
	case SMB_ACL_DELETE:
	    for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
		bool found = False;

		for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
		    if (security_ace_equal(&sd->dacl->aces[i],
					   &old->dacl->aces[j])) {
			uint32_t k;
			for (k=j; k<old->dacl->num_aces-1;k++) {
			    old->dacl->aces[k] = old->dacl->aces[k+1];
			}
			old->dacl->num_aces--;
			found = True;
			break;
		    }
		}

		if (!found) {
			printf("ACL for ACE:");
			print_ace(NULL, stdout, &sd->dacl->aces[i], false);
			printf(" not found\n");
		}
	    }
	    break;
	case SMB_ACL_MODIFY:
	    for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
		bool found = False;

		for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
		    if (dom_sid_equal(&sd->dacl->aces[i].trustee,
			&old->dacl->aces[j].trustee)) {
			old->dacl->aces[j] = sd->dacl->aces[i];
			found = True;
		    }
		}

		if (!found) {
		    printf("ACL for SID %s not found\n",
			   sid_string_tos(&sd->dacl->aces[i].trustee));
		}
	    }

	    if (sd->owner_sid) {
		old->owner_sid = sd->owner_sid;
	    }

	    if (sd->group_sid) {
		old->group_sid = sd->group_sid;
	    }
	    break;
	case SMB_ACL_ADD:
	    for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
		add_ace(mem_ctx, &old->dacl, &sd->dacl->aces[i]);
	    }
	    break;
	case SMB_ACL_SET:
	    old = sd;
	    break;
	case SMB_SD_DELETE:
	    if (!delete_share_security(sharename)) {
		fprintf( stderr, "Failed to delete security descriptor for "
			 "share [%s]\n", sharename );
		return -1;
	    }
	    return 0;
	default:
		fprintf(stderr, "invalid command\n");
		return -1;
	}

	/* Denied ACE entries must come before allowed ones */
	sort_acl(old->dacl);

	if ( !set_share_security( sharename, old ) ) {
	    fprintf( stderr, "Failed to store acl for share [%s]\n", sharename );
	    return 2;
	}
	return 0;
}

static int set_sharesec_sddl(const char *sharename, const char *sddl)
{
	struct security_descriptor *sd;
	bool ret;

	sd = sddl_decode(talloc_tos(), sddl, get_global_sam_sid());
	if (sd == NULL) {
		fprintf(stderr, "Failed to parse acl\n");
		return -1;
	}

	ret = set_share_security(sharename, sd);
	TALLOC_FREE(sd);
	if (!ret) {
		fprintf(stderr, "Failed to store acl for share [%s]\n",
			sharename);
		return -1;
	}

	return 0;
}

static int view_sharesec_sddl(const char *sharename)
{
	struct security_descriptor *sd;
	size_t sd_size;
	char *acl;

	sd = get_share_security(talloc_tos(), sharename, &sd_size);
	if (sd == NULL) {
		fprintf(stderr, "Unable to retrieve permissions for share "
			"[%s]\n", sharename);
		return -1;
	}

	acl = sddl_encode(talloc_tos(), sd, get_global_sam_sid());
	TALLOC_FREE(sd);
	if (acl == NULL) {
		fprintf(stderr, "Unable to sddl-encode permissions for share "
			"[%s]\n", sharename);
		return -1;
	}
	printf("%s\n", acl);
	TALLOC_FREE(acl);
	return 0;
}

/********************************************************************
  main program
********************************************************************/

enum {
	OPT_VIEW_ALL = 1000,
};

int main(int argc, const char *argv[])
{
	int opt;
	int retval = 0;
	enum acl_mode mode = SMB_ACL_SET;
	static char *the_acl = NULL;
	fstring sharename;
	bool force_acl = False;
	int snum;
	poptContext pc;
	bool initialize_sid = False;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "remove", 'r', POPT_ARG_STRING, &the_acl, 'r', "Remove ACEs", "ACL" },
		{ "modify", 'm', POPT_ARG_STRING, &the_acl, 'm', "Modify existing ACEs", "ACL" },
		{ "add", 'a', POPT_ARG_STRING, &the_acl, 'a', "Add ACEs", "ACL" },
		{ "replace", 'R', POPT_ARG_STRING, &the_acl, 'R', "Overwrite share permission ACL", "ACLS" },
		{ "delete", 'D', POPT_ARG_NONE, NULL, 'D', "Delete the entire security descriptor" },
		{ "setsddl", 'S', POPT_ARG_STRING, the_acl, 'S',
		  "Set the SD in sddl format" },
		{ "viewsddl", 'V', POPT_ARG_NONE, the_acl, 'V',
		  "View the SD in sddl format" },
		{ "view", 'v', POPT_ARG_NONE, NULL, 'v', "View current share permissions" },
		{ "view-all", 0, POPT_ARG_NONE, NULL, OPT_VIEW_ALL,
		  "View all current share permissions" },
		{ "machine-sid", 'M', POPT_ARG_NONE, NULL, 'M', "Initialize the machine SID" },
		{ "force", 'F', POPT_ARG_NONE, NULL, 'F', "Force storing the ACL", "ACLS" },
		POPT_COMMON_SAMBA
		{ NULL }
	};

	if ( !(ctx = talloc_stackframe()) ) {
		fprintf( stderr, "Failed to initialize talloc context!\n");
		return -1;
	}

	/* set default debug level to 1 regardless of what smb.conf sets */
	setup_logging( "sharesec", DEBUG_STDERR);

	smb_init_locale();

	lp_set_cmdline("log level", "1");

	pc = poptGetContext("sharesec", argc, argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "sharename\n");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'r':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_DELETE;
			break;

		case 'm':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_MODIFY;
			break;

		case 'a':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_ADD;
			break;

		case 'R':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_SET;
			break;

		case 'D':
			mode = SMB_SD_DELETE;
			break;

		case 'S':
			mode = SMB_SD_SETSDDL;
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			break;

		case 'V':
			mode = SMB_SD_VIEWSDDL;
			break;

		case 'v':
			mode = SMB_ACL_VIEW;
			break;

		case 'F':
			force_acl = True;
			break;

		case 'M':
			initialize_sid = True;
			break;
		case OPT_VIEW_ALL:
			mode = SMB_ACL_VIEW_ALL;
			break;
		}
	}

	setlinebuf(stdout);

	lp_load_with_registry_shares(get_dyn_CONFIGFILE());

	/* check for initializing secrets.tdb first */

	if ( initialize_sid ) {
		struct dom_sid *sid = get_global_sam_sid();

		if ( !sid ) {
			fprintf( stderr, "Failed to retrieve Machine SID!\n");
			return 3;
		}

		printf ("%s\n", sid_string_tos( sid ) );
		return 0;
	}

	if ( mode == SMB_ACL_VIEW && force_acl ) {
		fprintf( stderr, "Invalid combination of -F and -v\n");
		return -1;
	}

	if (mode == SMB_ACL_VIEW_ALL) {
		int i;

		for (i=0; i<lp_numservices(); i++) {
			TALLOC_CTX *frame = talloc_stackframe();
			const char *service = lp_servicename(frame, i);

			if (service == NULL) {
				continue;
			}

			printf("[%s]\n", service);
			change_share_sec(frame, service, NULL, SMB_ACL_VIEW);
			printf("\n");
			TALLOC_FREE(frame);
		}
		goto done;
	}

	/* get the sharename */

	if(!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	fstrcpy(sharename, poptGetArg(pc));

	snum = lp_servicenumber( sharename );

	if ( snum == -1 && !force_acl ) {
		fprintf( stderr, "Invalid sharename: %s\n", sharename);
		return -1;
	}

	switch (mode) {
	case SMB_SD_SETSDDL:
		retval = set_sharesec_sddl(sharename, the_acl);
		break;
	case SMB_SD_VIEWSDDL:
		retval = view_sharesec_sddl(sharename);
		break;
	default:
		retval = change_share_sec(ctx, sharename, the_acl, mode);
		break;
	}

done:
	talloc_destroy(ctx);

	return retval;
}
