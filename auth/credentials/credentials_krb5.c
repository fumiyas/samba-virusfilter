/* 
   Unix SMB/CIFS implementation.

   Handle user credentials (as regards krb5)

   Copyright (C) Jelmer Vernooij 2005
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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
#include "system/kerberos.h"
#include "system/gssapi.h"
#include "auth/kerberos/kerberos.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include "auth/credentials/credentials_proto.h"
#include "auth/credentials/credentials_krb5.h"
#include "auth/kerberos/kerberos_credentials.h"
#include "auth/kerberos/kerberos_srv_keytab.h"
#include "auth/kerberos/kerberos_util.h"
#include "auth/kerberos/pac_utils.h"
#include "param/param.h"

static void cli_credentials_invalidate_client_gss_creds(
					struct cli_credentials *cred,
					enum credentials_obtained obtained);

_PUBLIC_ int cli_credentials_get_krb5_context(struct cli_credentials *cred, 
				     struct loadparm_context *lp_ctx,
				     struct smb_krb5_context **smb_krb5_context) 
{
	int ret;
	if (cred->smb_krb5_context) {
		*smb_krb5_context = cred->smb_krb5_context;
		return 0;
	}

	ret = smb_krb5_init_context(cred, lp_ctx,
				    &cred->smb_krb5_context);
	if (ret) {
		cred->smb_krb5_context = NULL;
		return ret;
	}
	*smb_krb5_context = cred->smb_krb5_context;
	return 0;
}

/* For most predictable behaviour, this needs to be called directly after the cli_credentials_init(),
 * otherwise we may still have references to the old smb_krb5_context in a credential cache etc
 */
_PUBLIC_ NTSTATUS cli_credentials_set_krb5_context(struct cli_credentials *cred, 
					  struct smb_krb5_context *smb_krb5_context)
{
	if (smb_krb5_context == NULL) {
		talloc_unlink(cred, cred->smb_krb5_context);
		cred->smb_krb5_context = NULL;
		return NT_STATUS_OK;
	}

	if (!talloc_reference(cred, smb_krb5_context)) {
		return NT_STATUS_NO_MEMORY;
	}
	cred->smb_krb5_context = smb_krb5_context;
	return NT_STATUS_OK;
}

static int cli_credentials_set_from_ccache(struct cli_credentials *cred, 
					   struct ccache_container *ccache,
					   enum credentials_obtained obtained,
					   const char **error_string)
{
	
	krb5_principal princ;
	krb5_error_code ret;
	char *name;

	if (cred->ccache_obtained > obtained) {
		return 0;
	}

	ret = krb5_cc_get_principal(ccache->smb_krb5_context->krb5_context, 
				    ccache->ccache, &princ);

	if (ret) {
		(*error_string) = talloc_asprintf(cred, "failed to get principal from ccache: %s\n",
						  smb_get_krb5_error_message(ccache->smb_krb5_context->krb5_context,
									     ret, cred));
		return ret;
	}
	
	ret = krb5_unparse_name(ccache->smb_krb5_context->krb5_context, princ, &name);
	if (ret) {
		(*error_string) = talloc_asprintf(cred, "failed to unparse principal from ccache: %s\n",
						  smb_get_krb5_error_message(ccache->smb_krb5_context->krb5_context,
									     ret, cred));
		return ret;
	}

	cli_credentials_set_principal(cred, name, obtained);

	free(name);

	krb5_free_principal(ccache->smb_krb5_context->krb5_context, princ);

	/* set the ccache_obtained here, as it just got set to UNINITIALISED by the calls above */
	cred->ccache_obtained = obtained;

	return 0;
}

/* Free a memory ccache */
static int free_mccache(struct ccache_container *ccc)
{
	krb5_cc_destroy(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

/* Free a disk-based ccache */
static int free_dccache(struct ccache_container *ccc) {
	krb5_cc_close(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

_PUBLIC_ int cli_credentials_set_ccache(struct cli_credentials *cred, 
					struct loadparm_context *lp_ctx,
					const char *name,
					enum credentials_obtained obtained,
					const char **error_string)
{
	krb5_error_code ret;
	krb5_principal princ;
	struct ccache_container *ccc;
	if (cred->ccache_obtained > obtained) {
		return 0;
	}

	ccc = talloc(cred, struct ccache_container);
	if (!ccc) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}

	ret = cli_credentials_get_krb5_context(cred, lp_ctx,
					       &ccc->smb_krb5_context);
	if (ret) {
		(*error_string) = error_message(ret);
		talloc_free(ccc);
		return ret;
	}
	if (!talloc_reference(ccc, ccc->smb_krb5_context)) {
		talloc_free(ccc);
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}

	if (name) {
		ret = krb5_cc_resolve(ccc->smb_krb5_context->krb5_context, name, &ccc->ccache);
		if (ret) {
			(*error_string) = talloc_asprintf(cred, "failed to read krb5 ccache: %s: %s\n",
							  name,
							  smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context,
										     ret, ccc));
			talloc_free(ccc);
			return ret;
		}
	} else {
		ret = krb5_cc_default(ccc->smb_krb5_context->krb5_context, &ccc->ccache);
		if (ret) {
			(*error_string) = talloc_asprintf(cred, "failed to read default krb5 ccache: %s\n",
							  smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context,
										     ret, ccc));
			talloc_free(ccc);
			return ret;
		}
	}

	talloc_set_destructor(ccc, free_dccache);

	ret = krb5_cc_get_principal(ccc->smb_krb5_context->krb5_context, ccc->ccache, &princ);

	if (ret == 0) {
		krb5_free_principal(ccc->smb_krb5_context->krb5_context, princ);
		ret = cli_credentials_set_from_ccache(cred, ccc, obtained, error_string);

		if (ret) {
			(*error_string) = error_message(ret);
			return ret;
		}

		cred->ccache = ccc;
		cred->ccache_obtained = obtained;
		talloc_steal(cred, ccc);

		cli_credentials_invalidate_client_gss_creds(cred, cred->ccache_obtained);
		return 0;
	}
	return 0;
}

/*
 * Indicate the we failed to log in to this service/host with these
 * credentials.  The caller passes an unsigned int which they
 * initialise to the number of times they would like to retry.
 *
 * This method is used to support re-trying with freshly fetched
 * credentials in case a server is rebuilt while clients have
 * non-expired tickets. When the client code gets a logon failure they
 * throw away the existing credentials for the server and retry.
 */
_PUBLIC_ bool cli_credentials_failed_kerberos_login(struct cli_credentials *cred,
						    const char *principal,
						    unsigned int *count)
{
	struct ccache_container *ccc;
	krb5_creds creds, creds2;
	int ret;

	if (principal == NULL) {
		/* no way to delete if we don't know the principal */
		return false;
	}

	ccc = cred->ccache;
	if (ccc == NULL) {
		/* not a kerberos connection */
		return false;
	}

	if (*count > 0) {
		/* We have already tried discarding the credentials */
		return false;
	}
	(*count)++;

	ZERO_STRUCT(creds);
	ret = krb5_parse_name(ccc->smb_krb5_context->krb5_context, principal, &creds.server);
	if (ret != 0) {
		return false;
	}

	ret = krb5_cc_retrieve_cred(ccc->smb_krb5_context->krb5_context, ccc->ccache, KRB5_TC_MATCH_SRV_NAMEONLY, &creds, &creds2);
	if (ret != 0) {
		/* don't retry - we didn't find these credentials to remove */
		krb5_free_cred_contents(ccc->smb_krb5_context->krb5_context, &creds);
		return false;
	}

	ret = krb5_cc_remove_cred(ccc->smb_krb5_context->krb5_context, ccc->ccache, KRB5_TC_MATCH_SRV_NAMEONLY, &creds);
	krb5_free_cred_contents(ccc->smb_krb5_context->krb5_context, &creds);
	krb5_free_cred_contents(ccc->smb_krb5_context->krb5_context, &creds2);
	if (ret != 0) {
		/* don't retry - we didn't find these credentials to
		 * remove. Note that with the current backend this
		 * never happens, as it always returns 0 even if the
		 * creds don't exist, which is why we do a separate
		 * krb5_cc_retrieve_cred() above.
		 */
		return false;
	}
	return true;
}


static int cli_credentials_new_ccache(struct cli_credentials *cred, 
				      struct loadparm_context *lp_ctx,
				      char *ccache_name,
				      struct ccache_container **_ccc,
				      const char **error_string)
{
	bool must_free_cc_name = false;
	krb5_error_code ret;
	struct ccache_container *ccc = talloc(cred, struct ccache_container);
	if (!ccc) {
		return ENOMEM;
	}

	ret = cli_credentials_get_krb5_context(cred, lp_ctx,
					       &ccc->smb_krb5_context);
	if (ret) {
		talloc_free(ccc);
		(*error_string) = talloc_asprintf(cred, "Failed to get krb5_context: %s",
						  error_message(ret));
		return ret;
	}
	if (!talloc_reference(ccc, ccc->smb_krb5_context)) {
		talloc_free(ccc);
		(*error_string) = strerror(ENOMEM);
		return ENOMEM;
	}

	if (!ccache_name) {
		must_free_cc_name = true;

		if (lpcfg_parm_bool(lp_ctx, NULL, "credentials", "krb5_cc_file", false)) {
			ccache_name = talloc_asprintf(ccc, "FILE:/tmp/krb5_cc_samba_%u_%p", 
						      (unsigned int)getpid(), ccc);
		} else {
			ccache_name = talloc_asprintf(ccc, "MEMORY:%p", 
						      ccc);
		}

		if (!ccache_name) {
			talloc_free(ccc);
			(*error_string) = strerror(ENOMEM);
			return ENOMEM;
		}
	}

	ret = krb5_cc_resolve(ccc->smb_krb5_context->krb5_context, ccache_name, 
			      &ccc->ccache);
	if (ret) {
		(*error_string) = talloc_asprintf(cred, "failed to resolve a krb5 ccache (%s): %s\n",
						  ccache_name,
						  smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context,
									     ret, ccc));
		talloc_free(ccache_name);
		talloc_free(ccc);
		return ret;
	}

	if (strncasecmp(ccache_name, "MEMORY:", 7) == 0) {
		talloc_set_destructor(ccc, free_mccache);
	} else {
		talloc_set_destructor(ccc, free_dccache);
	}

	if (must_free_cc_name) {
		talloc_free(ccache_name);
	}

	*_ccc = ccc;

	return 0;
}

_PUBLIC_ int cli_credentials_get_named_ccache(struct cli_credentials *cred, 
					      struct tevent_context *event_ctx,
					      struct loadparm_context *lp_ctx,
					      char *ccache_name,
					      struct ccache_container **ccc,
					      const char **error_string)
{
	krb5_error_code ret;
	enum credentials_obtained obtained;
	
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred, lp_ctx);
	}

	if (cred->ccache_obtained >= cred->ccache_threshold && 
	    cred->ccache_obtained > CRED_UNINITIALISED) {
		time_t lifetime;
		bool expired = false;
		ret = smb_krb5_cc_get_lifetime(cred->ccache->smb_krb5_context->krb5_context,
					       cred->ccache->ccache, &lifetime);
		if (ret == KRB5_CC_END) {
			/* If we have a particular ccache set, without
			 * an initial ticket, then assume there is a
			 * good reason */
		} else if (ret == 0) {
			if (lifetime == 0) {
				DEBUG(3, ("Ticket in credentials cache for %s expired, will refresh\n",
					  cli_credentials_get_principal(cred, cred)));
				expired = true;
			} else if (lifetime < 300) {
				DEBUG(3, ("Ticket in credentials cache for %s will shortly expire (%u secs), will refresh\n", 
					  cli_credentials_get_principal(cred, cred), (unsigned int)lifetime));
				expired = true;
			}
		} else {
			(*error_string) = talloc_asprintf(cred, "failed to get ccache lifetime: %s\n",
							  smb_get_krb5_error_message(cred->ccache->smb_krb5_context->krb5_context,
										     ret, cred));
			return ret;
		}

		DEBUG(5, ("Ticket in credentials cache for %s will expire in %u secs\n", 
			  cli_credentials_get_principal(cred, cred), (unsigned int)lifetime));
		
		if (!expired) {
			*ccc = cred->ccache;
			return 0;
		}
	}
	if (cli_credentials_is_anonymous(cred)) {
		(*error_string) = "Cannot get anonymous kerberos credentials";
		return EINVAL;
	}

	ret = cli_credentials_new_ccache(cred, lp_ctx, ccache_name, ccc, error_string);
	if (ret) {
		return ret;
	}

	ret = kinit_to_ccache(cred, cred, (*ccc)->smb_krb5_context, event_ctx, (*ccc)->ccache, &obtained, error_string);
	if (ret) {
		return ret;
	}

	ret = cli_credentials_set_from_ccache(cred, *ccc, 
					      obtained, error_string);
	
	cred->ccache = *ccc;
	cred->ccache_obtained = cred->principal_obtained;
	if (ret) {
		return ret;
	}
	cli_credentials_invalidate_client_gss_creds(cred, cred->ccache_obtained);
	return 0;
}

_PUBLIC_ int cli_credentials_get_ccache(struct cli_credentials *cred, 
					struct tevent_context *event_ctx,
					struct loadparm_context *lp_ctx,
					struct ccache_container **ccc,
					const char **error_string)
{
	return cli_credentials_get_named_ccache(cred, event_ctx, lp_ctx, NULL, ccc, error_string);
}

/* We have good reason to think the ccache in these credentials is invalid - blow it away */
static void cli_credentials_unconditionally_invalidate_client_gss_creds(struct cli_credentials *cred)
{
	if (cred->client_gss_creds_obtained > CRED_UNINITIALISED) {
		talloc_unlink(cred, cred->client_gss_creds);
		cred->client_gss_creds = NULL;
	}
	cred->client_gss_creds_obtained = CRED_UNINITIALISED;
}

void cli_credentials_invalidate_client_gss_creds(struct cli_credentials *cred, 
						 enum credentials_obtained obtained)
{
	/* If the caller just changed the username/password etc, then
	 * any cached credentials are now invalid */
	if (obtained >= cred->client_gss_creds_obtained) {
		if (cred->client_gss_creds_obtained > CRED_UNINITIALISED) {
			talloc_unlink(cred, cred->client_gss_creds);
			cred->client_gss_creds = NULL;
		}
		cred->client_gss_creds_obtained = CRED_UNINITIALISED;
	}
	/* Now that we know that the data is 'this specified', then
	 * don't allow something less 'known' to be returned as a
	 * ccache.  Ie, if the username is on the command line, we
	 * don't want to later guess to use a file-based ccache */
	if (obtained > cred->client_gss_creds_threshold) {
		cred->client_gss_creds_threshold = obtained;
	}
}

/* We have good reason to think this CCACHE is invalid.  Blow it away */
static void cli_credentials_unconditionally_invalidate_ccache(struct cli_credentials *cred)
{
	if (cred->ccache_obtained > CRED_UNINITIALISED) {
		talloc_unlink(cred, cred->ccache);
		cred->ccache = NULL;
	}
	cred->ccache_obtained = CRED_UNINITIALISED;

	cli_credentials_unconditionally_invalidate_client_gss_creds(cred);
}

_PUBLIC_ void cli_credentials_invalidate_ccache(struct cli_credentials *cred, 
				       enum credentials_obtained obtained)
{
	/* If the caller just changed the username/password etc, then
	 * any cached credentials are now invalid */
	if (obtained >= cred->ccache_obtained) {
		if (cred->ccache_obtained > CRED_UNINITIALISED) {
			talloc_unlink(cred, cred->ccache);
			cred->ccache = NULL;
		}
		cred->ccache_obtained = CRED_UNINITIALISED;
	}
	/* Now that we know that the data is 'this specified', then
	 * don't allow something less 'known' to be returned as a
	 * ccache.  i.e, if the username is on the command line, we
	 * don't want to later guess to use a file-based ccache */
	if (obtained > cred->ccache_threshold) {
		cred->ccache_threshold  = obtained;
	}

	cli_credentials_invalidate_client_gss_creds(cred, 
						    obtained);
}

static int free_gssapi_creds(struct gssapi_creds_container *gcc)
{
	OM_uint32 min_stat;
	(void)gss_release_cred(&min_stat, &gcc->creds);
	return 0;
}

_PUBLIC_ int cli_credentials_get_client_gss_creds(struct cli_credentials *cred, 
						  struct tevent_context *event_ctx,
						  struct loadparm_context *lp_ctx,
						  struct gssapi_creds_container **_gcc,
						  const char **error_string)
{
	int ret = 0;
	OM_uint32 maj_stat, min_stat;
	struct gssapi_creds_container *gcc;
	struct ccache_container *ccache;
#ifdef HAVE_GSS_KRB5_CRED_NO_CI_FLAGS_X
	gss_buffer_desc empty_buffer = GSS_C_EMPTY_BUFFER;
#endif
	krb5_enctype *etypes = NULL;

	if (cred->client_gss_creds_obtained >= cred->client_gss_creds_threshold && 
	    cred->client_gss_creds_obtained > CRED_UNINITIALISED) {
		bool expired = false;
		OM_uint32 lifetime = 0;
		gss_cred_usage_t usage = 0;
		maj_stat = gss_inquire_cred(&min_stat, cred->client_gss_creds->creds, 
					    NULL, &lifetime, &usage, NULL);
		if (maj_stat == GSS_S_CREDENTIALS_EXPIRED) {
			DEBUG(3, ("Credentials for %s expired, must refresh credentials cache\n", cli_credentials_get_principal(cred, cred)));
			expired = true;
		} else if (maj_stat == GSS_S_COMPLETE && lifetime < 300) {
			DEBUG(3, ("Credentials for %s will expire shortly (%u sec), must refresh credentials cache\n", cli_credentials_get_principal(cred, cred), lifetime));
			expired = true;
		} else if (maj_stat != GSS_S_COMPLETE) {
			*error_string = talloc_asprintf(cred, "inquiry of credential lifefime via GSSAPI gss_inquire_cred failed: %s\n",
							gssapi_error_string(cred, maj_stat, min_stat, NULL));
			return EINVAL;
		}
		if (expired) {
			cli_credentials_unconditionally_invalidate_client_gss_creds(cred);
		} else {
			DEBUG(5, ("GSSAPI credentials for %s will expire in %u secs\n", 
				  cli_credentials_get_principal(cred, cred), (unsigned int)lifetime));
		
			*_gcc = cred->client_gss_creds;
			return 0;
		}
	}

	ret = cli_credentials_get_ccache(cred, event_ctx, lp_ctx,
					 &ccache, error_string);
	if (ret) {
		if (cli_credentials_get_kerberos_state(cred) == CRED_MUST_USE_KERBEROS) {
			DEBUG(1, ("Failed to get kerberos credentials (kerberos required): %s\n", *error_string));
		} else {
			DEBUG(4, ("Failed to get kerberos credentials: %s\n", *error_string));
		}
		return ret;
	}

	gcc = talloc(cred, struct gssapi_creds_container);
	if (!gcc) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}

	maj_stat = gss_krb5_import_cred(&min_stat, ccache->ccache, NULL, NULL, 
					&gcc->creds);
	if ((maj_stat == GSS_S_FAILURE) && (min_stat == (OM_uint32)KRB5_CC_END || min_stat == (OM_uint32) KRB5_CC_NOTFOUND)) {
		/* This CCACHE is no good.  Ensure we don't use it again */
		cli_credentials_unconditionally_invalidate_ccache(cred);

		/* Now try again to get a ccache */
		ret = cli_credentials_get_ccache(cred, event_ctx, lp_ctx,
						 &ccache, error_string);
		if (ret) {
			DEBUG(1, ("Failed to re-get CCACHE for GSSAPI client: %s\n", error_message(ret)));
			return ret;
		}

		maj_stat = gss_krb5_import_cred(&min_stat, ccache->ccache, NULL, NULL,
						&gcc->creds);

	}

	if (maj_stat) {
		talloc_free(gcc);
		if (min_stat) {
			ret = min_stat;
		} else {
			ret = EINVAL;
		}
		(*error_string) = talloc_asprintf(cred, "gss_krb5_import_cred failed: %s", error_message(ret));
		return ret;
	}


	/*
	 * transfer the enctypes from the smb_krb5_context to the gssapi layer
	 *
	 * We use 'our' smb_krb5_context to do the AS-REQ and it is possible
	 * to configure the enctypes via the krb5.conf.
	 *
	 * And the gss_init_sec_context() creates it's own krb5_context and
	 * the TGS-REQ had all enctypes in it and only the ones configured
	 * and used for the AS-REQ, so it wasn't possible to disable the usage
	 * of AES keys.
	 */
	min_stat = smb_krb5_get_allowed_etypes(ccache->smb_krb5_context->krb5_context,
					       &etypes);
	if (min_stat == 0) {
		OM_uint32 num_ktypes;

		for (num_ktypes = 0; etypes[num_ktypes]; num_ktypes++);

		maj_stat = gss_krb5_set_allowable_enctypes(&min_stat, gcc->creds,
							   num_ktypes,
							   (int32_t *) etypes);
		SAFE_FREE(etypes);
		if (maj_stat) {
			talloc_free(gcc);
			if (min_stat) {
				ret = min_stat;
			} else {
				ret = EINVAL;
			}
			(*error_string) = talloc_asprintf(cred, "gss_krb5_set_allowable_enctypes failed: %s", error_message(ret));
			return ret;
		}
	}

#ifdef HAVE_GSS_KRB5_CRED_NO_CI_FLAGS_X
	/*
	 * Don't force GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG.
	 *
	 * This allows us to disable SIGN and SEAL on a TLS connection with
	 * GSS-SPNENO. For example ldaps:// connections.
	 *
	 * https://groups.yahoo.com/neo/groups/cat-ietf/conversations/topics/575
	 * http://krbdev.mit.edu/rt/Ticket/Display.html?id=6938
	 */
	maj_stat = gss_set_cred_option(&min_stat, &gcc->creds,
				       GSS_KRB5_CRED_NO_CI_FLAGS_X,
				       &empty_buffer);
	if (maj_stat) {
		talloc_free(gcc);
		if (min_stat) {
			ret = min_stat;
		} else {
			ret = EINVAL;
		}
		(*error_string) = talloc_asprintf(cred, "gss_set_cred_option failed: %s", error_message(ret));
		return ret;
	}
#endif
	cred->client_gss_creds_obtained = cred->ccache_obtained;
	talloc_set_destructor(gcc, free_gssapi_creds);
	cred->client_gss_creds = gcc;
	*_gcc = gcc;
	return 0;
}

/**
   Set a gssapi cred_id_t into the credentials system. (Client case)

   This grabs the credentials both 'intact' and getting the krb5
   ccache out of it.  This routine can be generalised in future for
   the case where we deal with GSSAPI mechs other than krb5.  

   On sucess, the caller must not free gssapi_cred, as it now belongs
   to the credentials system.
*/

 int cli_credentials_set_client_gss_creds(struct cli_credentials *cred, 
					  struct loadparm_context *lp_ctx,
					  gss_cred_id_t gssapi_cred,
					  enum credentials_obtained obtained,
					  const char **error_string)
{
	int ret;
	OM_uint32 maj_stat, min_stat;
	struct ccache_container *ccc;
	struct gssapi_creds_container *gcc;
	if (cred->client_gss_creds_obtained > obtained) {
		return 0;
	}

	gcc = talloc(cred, struct gssapi_creds_container);
	if (!gcc) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}

	ret = cli_credentials_new_ccache(cred, lp_ctx, NULL, &ccc, error_string);
	if (ret != 0) {
		return ret;
	}

	maj_stat = gss_krb5_copy_ccache(&min_stat, 
					gssapi_cred, ccc->ccache);
	if (maj_stat) {
		if (min_stat) {
			ret = min_stat;
		} else {
			ret = EINVAL;
		}
		if (ret) {
			(*error_string) = error_message(ENOMEM);
		}
	}

	if (ret == 0) {
		ret = cli_credentials_set_from_ccache(cred, ccc, obtained, error_string);
	}
	cred->ccache = ccc;
	cred->ccache_obtained = obtained;
	if (ret == 0) {
		gcc->creds = gssapi_cred;
		talloc_set_destructor(gcc, free_gssapi_creds);
		
		/* set the clinet_gss_creds_obtained here, as it just 
		   got set to UNINITIALISED by the calls above */
		cred->client_gss_creds_obtained = obtained;
		cred->client_gss_creds = gcc;
	}
	return ret;
}

static int cli_credentials_shallow_ccache(struct cli_credentials *cred)
{
	krb5_error_code ret;
	const struct ccache_container *old_ccc = NULL;
	struct ccache_container *ccc = NULL;
	char *ccache_name = NULL;

	old_ccc = cred->ccache;
	if (old_ccc == NULL) {
		return 0;
	}

	ccc = talloc(cred, struct ccache_container);
	if (ccc == NULL) {
		return ENOMEM;
	}
	*ccc = *old_ccc;
	ccc->ccache = NULL;

	ccache_name = talloc_asprintf(ccc, "MEMORY:%p", ccc);

	ret = krb5_cc_resolve(ccc->smb_krb5_context->krb5_context,
			      ccache_name, &ccc->ccache);
	if (ret != 0) {
		TALLOC_FREE(ccc);
		return ret;
	}

	talloc_set_destructor(ccc, free_mccache);

	TALLOC_FREE(ccache_name);

	ret = smb_krb5_cc_copy_creds(ccc->smb_krb5_context->krb5_context,
				     old_ccc->ccache, ccc->ccache);
	if (ret != 0) {
		TALLOC_FREE(ccc);
		return ret;
	}

	cred->ccache = ccc;
	cred->client_gss_creds = NULL;
	cred->client_gss_creds_obtained = CRED_UNINITIALISED;
	return ret;
}

_PUBLIC_ struct cli_credentials *cli_credentials_shallow_copy(TALLOC_CTX *mem_ctx,
						struct cli_credentials *src)
{
	struct cli_credentials *dst;
	int ret;

	dst = talloc(mem_ctx, struct cli_credentials);
	if (dst == NULL) {
		return NULL;
	}

	*dst = *src;

	ret = cli_credentials_shallow_ccache(dst);
	if (ret != 0) {
		TALLOC_FREE(dst);
		return NULL;
	}

	return dst;
}

static int smb_krb5_create_salt_principal(TALLOC_CTX *mem_ctx,
					  const char *samAccountName,
					  const char *realm,
					  const char **salt_principal,
					  const char **error_string)
{
	char *machine_username;
	bool is_machine_account = false;
	char *upper_realm;
	TALLOC_CTX *tmp_ctx;
	int rc = -1;

	if (samAccountName == NULL) {
		*error_string = "Cannot determine salt principal, no "
				"saltPrincipal or samAccountName specified";
		return rc;
	}

	if (realm == NULL) {
		*error_string = "Cannot make principal without a realm";
		return rc;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		*error_string = "Cannot allocate talloc context";
		return rc;
	}

	upper_realm = strupper_talloc(tmp_ctx, realm);
	if (upper_realm == NULL) {
		*error_string = "Cannot allocate to upper case realm";
		goto out;
	}

	machine_username = strlower_talloc(tmp_ctx, samAccountName);
	if (!machine_username) {
		*error_string = "Cannot duplicate samAccountName";
		goto out;
	}

	if (machine_username[strlen(machine_username) - 1] == '$') {
		machine_username[strlen(machine_username) - 1] = '\0';
		is_machine_account = true;
	}

	if (is_machine_account) {
		char *lower_realm;

		lower_realm = strlower_talloc(tmp_ctx, realm);
		if (lower_realm == NULL) {
			*error_string = "Cannot allocate to lower case realm";
			goto out;
		}

		*salt_principal = talloc_asprintf(mem_ctx,
						  "host/%s.%s@%s",
						  machine_username,
						  lower_realm,
						  upper_realm);
	} else {
		*salt_principal = talloc_asprintf(mem_ctx,
						  "%s@%s",
						  machine_username,
						  upper_realm);
	}
	if (*salt_principal == NULL) {
		*error_string = "Cannot create salt principal";
		goto out;
	}

	rc = 0;
out:
	talloc_free(tmp_ctx);
	return rc;
}

/* Get the keytab (actually, a container containing the krb5_keytab)
 * attached to this context.  If this hasn't been done or set before,
 * it will be generated from the password.
 */
_PUBLIC_ int cli_credentials_get_keytab(struct cli_credentials *cred, 
					struct loadparm_context *lp_ctx,
					struct keytab_container **_ktc)
{
	krb5_error_code ret;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;
	const char *keytab_name;
	krb5_keytab keytab;
	TALLOC_CTX *mem_ctx;
	const char *username = cli_credentials_get_username(cred);
	const char *realm = cli_credentials_get_realm(cred);
	const char *error_string;
	const char *salt_principal;

	if (cred->keytab_obtained >= (MAX(cred->principal_obtained, 
					  cred->username_obtained))) {
		*_ktc = cred->keytab;
		return 0;
	}

	if (cli_credentials_is_anonymous(cred)) {
		return EINVAL;
	}

	ret = cli_credentials_get_krb5_context(cred, lp_ctx,
					       &smb_krb5_context);
	if (ret) {
		return ret;
	}

	mem_ctx = talloc_new(cred);
	if (!mem_ctx) {
		return ENOMEM;
	}

	/*
	 * FIXME: Currently there is no better way than to create the correct
	 * salt principal by checking if the username ends with a '$'. It would
	 * be better if it is part of the credentials.
	 */
	ret = smb_krb5_create_salt_principal(mem_ctx,
					     username,
					     realm,
					     &salt_principal,
					     &error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = smb_krb5_create_memory_keytab(mem_ctx,
					    smb_krb5_context->krb5_context,
					    cli_credentials_get_password(cred),
					    username,
					    realm,
					    salt_principal,
					    cli_credentials_get_kvno(cred),
					    &keytab,
					    &keytab_name);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = smb_krb5_get_keytab_container(mem_ctx, smb_krb5_context,
					    keytab, keytab_name, &ktc);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	cred->keytab_obtained = (MAX(cred->principal_obtained, 
				     cred->username_obtained));

	/* We make this keytab up based on a password.  Therefore
	 * match-by-key is acceptable, we can't match on the wrong
	 * principal */
	ktc->password_based = true;

	talloc_steal(cred, ktc);
	cred->keytab = ktc;
	*_ktc = cred->keytab;
	talloc_free(mem_ctx);
	return ret;
}

/* Given the name of a keytab (presumably in the format
 * FILE:/etc/krb5.keytab), open it and attach it */

_PUBLIC_ int cli_credentials_set_keytab_name(struct cli_credentials *cred, 
					     struct loadparm_context *lp_ctx,
					     const char *keytab_name,
					     enum credentials_obtained obtained)
{
	krb5_error_code ret;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;
	TALLOC_CTX *mem_ctx;

	if (cred->keytab_obtained >= obtained) {
		return 0;
	}

	ret = cli_credentials_get_krb5_context(cred, lp_ctx, &smb_krb5_context);
	if (ret) {
		return ret;
	}

	mem_ctx = talloc_new(cred);
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = smb_krb5_get_keytab_container(mem_ctx, smb_krb5_context,
					    NULL, keytab_name, &ktc);
	if (ret) {
		return ret;
	}

	cred->keytab_obtained = obtained;

	talloc_steal(cred, ktc);
	cred->keytab = ktc;
	talloc_free(mem_ctx);

	return ret;
}

/* Get server gss credentials (in gsskrb5, this means the keytab) */

_PUBLIC_ int cli_credentials_get_server_gss_creds(struct cli_credentials *cred, 
						  struct loadparm_context *lp_ctx,
						  struct gssapi_creds_container **_gcc)
{
	int ret = 0;
	OM_uint32 maj_stat, min_stat;
	struct gssapi_creds_container *gcc;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;
	TALLOC_CTX *mem_ctx;
	krb5_principal princ;
	const char *error_string;
	enum credentials_obtained obtained;

	mem_ctx = talloc_new(cred);
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = cli_credentials_get_krb5_context(cred, lp_ctx, &smb_krb5_context);
	if (ret) {
		return ret;
	}

	ret = principal_from_credentials(mem_ctx, cred, smb_krb5_context, &princ, &obtained, &error_string);
	if (ret) {
		DEBUG(1,("cli_credentials_get_server_gss_creds: making krb5 principal failed (%s)\n",
			 error_string));
		talloc_free(mem_ctx);
		return ret;
	}

	if (cred->server_gss_creds_obtained >= (MAX(cred->keytab_obtained, obtained))) {
		talloc_free(mem_ctx);
		*_gcc = cred->server_gss_creds;
		return 0;
	}

	ret = cli_credentials_get_keytab(cred, lp_ctx, &ktc);
	if (ret) {
		DEBUG(1, ("Failed to get keytab for GSSAPI server: %s\n", error_message(ret)));
		return ret;
	}

	gcc = talloc(cred, struct gssapi_creds_container);
	if (!gcc) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	if (ktc->password_based || obtained < CRED_SPECIFIED) {
		/* This creates a GSSAPI cred_id_t for match-by-key with only the keytab set */
		maj_stat = gss_krb5_import_cred(&min_stat, NULL, NULL, ktc->keytab,
						&gcc->creds);
	} else {
		/* This creates a GSSAPI cred_id_t with the principal and keytab set, matching by name */
		maj_stat = gss_krb5_import_cred(&min_stat, NULL, princ, ktc->keytab,
						&gcc->creds);
	}
	if (maj_stat) {
		if (min_stat) {
			ret = min_stat;
		} else {
			ret = EINVAL;
		}
	}
	if (ret == 0) {
		cred->server_gss_creds_obtained = cred->keytab_obtained;
		talloc_set_destructor(gcc, free_gssapi_creds);
		cred->server_gss_creds = gcc;
		*_gcc = gcc;
	}
	talloc_free(mem_ctx);
	return ret;
}

/** 
 * Set Kerberos KVNO
 */

_PUBLIC_ void cli_credentials_set_kvno(struct cli_credentials *cred,
			      int kvno)
{
	cred->kvno = kvno;
}

/**
 * Return Kerberos KVNO
 */

_PUBLIC_ int cli_credentials_get_kvno(struct cli_credentials *cred)
{
	return cred->kvno;
}


const char *cli_credentials_get_salt_principal(struct cli_credentials *cred) 
{
	return cred->salt_principal;
}

_PUBLIC_ void cli_credentials_set_salt_principal(struct cli_credentials *cred, const char *principal) 
{
	talloc_free(cred->salt_principal);
	cred->salt_principal = talloc_strdup(cred, principal);
}

/* The 'impersonate_principal' is used to allow one Kerberos principal
 * (and it's associated keytab etc) to impersonate another.  The
 * ability to do this is controlled by the KDC, but it is generally
 * permitted to impersonate anyone to yourself.  This allows any
 * member of the domain to get the groups of a user.  This is also
 * known as S4U2Self */

_PUBLIC_ const char *cli_credentials_get_impersonate_principal(struct cli_credentials *cred)
{
	return cred->impersonate_principal;
}

/*
 * The 'self_service' is the service principal that
 * represents the same object (by its objectSid)
 * as the client principal (typically our machine account).
 * When trying to impersonate 'impersonate_principal' with
 * S4U2Self.
 */
_PUBLIC_ const char *cli_credentials_get_self_service(struct cli_credentials *cred)
{
	return cred->self_service;
}

_PUBLIC_ void cli_credentials_set_impersonate_principal(struct cli_credentials *cred,
							const char *principal,
							const char *self_service)
{
	talloc_free(cred->impersonate_principal);
	cred->impersonate_principal = talloc_strdup(cred, principal);
	talloc_free(cred->self_service);
	cred->self_service = talloc_strdup(cred, self_service);
	cli_credentials_set_kerberos_state(cred, CRED_MUST_USE_KERBEROS);
}

/*
 * when impersonating for S4U2proxy we need to set the target principal.
 * Similarly, we may only be authorized to do general impersonation to
 * some particular services.
 *
 * Likewise, password changes typically require a ticket to kpasswd/realm directly, not via a TGT
 *
 * NULL means that tickets will be obtained for the krbtgt service.
*/

const char *cli_credentials_get_target_service(struct cli_credentials *cred)
{
	return cred->target_service;
}

_PUBLIC_ void cli_credentials_set_target_service(struct cli_credentials *cred, const char *target_service)
{
	talloc_free(cred->target_service);
	cred->target_service = talloc_strdup(cred, target_service);
}

