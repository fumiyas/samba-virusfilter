/* 
   ldb database library - ldif handlers for Samba

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Andrew Bartlett 2006-2009
   Copyright (C) Matthias Dieter Wallnöfer 2009
     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <ldb.h>
#include <ldb_module.h>
#include "ldb_handlers.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "librpc/ndr/libndr.h"
#include "libcli/security/security.h"
#include "param/param.h"
#include "../lib/util/asn1.h"

/*
  use ndr_print_* to convert a NDR formatted blob to a ldif formatted blob

  If mask_errors is true, then function succeeds but out data
  is set to "<Unable to decode binary data>" message

  \return 0 on success; -1 on error
*/
static int ldif_write_NDR(struct ldb_context *ldb, void *mem_ctx,
			  const struct ldb_val *in, struct ldb_val *out,
			  size_t struct_size,
			  ndr_pull_flags_fn_t pull_fn,
			  ndr_print_fn_t print_fn,
			  bool mask_errors)
{
	uint8_t *p;
	enum ndr_err_code err;
	if (!(ldb_get_flags(ldb) & LDB_FLG_SHOW_BINARY)) {
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}
	p = talloc_size(mem_ctx, struct_size);
	err = ndr_pull_struct_blob(in, mem_ctx, 
				   p, pull_fn);
	if (err != NDR_ERR_SUCCESS) {
		/* fail in not in mask_error mode */
		if (!mask_errors) {
			return -1;
		}
		talloc_free(p);
		out->data = (uint8_t *)talloc_strdup(mem_ctx, "<Unable to decode binary data>");
		out->length = strlen((const char *)out->data);
		return 0;
	}
	out->data = (uint8_t *)ndr_print_struct_string(mem_ctx, print_fn, "NDR", p);
	talloc_free(p);
	if (out->data == NULL) {
		return ldb_handler_copy(ldb, mem_ctx, in, out);		
	}
	out->length = strlen((char *)out->data);
	return 0;
}

/*
  convert a ldif formatted objectSid to a NDR formatted blob
*/
static int ldif_read_objectSid(struct ldb_context *ldb, void *mem_ctx,
			       const struct ldb_val *in, struct ldb_val *out)
{
	bool ret;
	enum ndr_err_code ndr_err;
	struct dom_sid sid;
	if (in->length > DOM_SID_STR_BUFLEN) {
		return -1;
	} else {
		char p[in->length+1];
		memcpy(p, in->data, in->length);
		p[in->length] = '\0';
		
		ret = dom_sid_parse(p, &sid);
		if (ret == false) {
			return -1;
		}
		
		*out = data_blob_talloc(mem_ctx, NULL,
					ndr_size_dom_sid(&sid, 0));
		if (out->data == NULL) {
			return -1;
		}
	
		ndr_err = ndr_push_struct_into_fixed_blob(out, &sid,
				(ndr_push_flags_fn_t)ndr_push_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return -1;
		}
	}
	return 0;
}

/*
  convert a NDR formatted blob to a ldif formatted objectSid
*/
int ldif_write_objectSid(struct ldb_context *ldb, void *mem_ctx,
				const struct ldb_val *in, struct ldb_val *out)
{
	struct dom_sid sid;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob_all_noalloc(in, &sid,
					   (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}
	*out = data_blob_string_const(dom_sid_string(mem_ctx, &sid));
	if (out->data == NULL) {
		return -1;
	}
	return 0;
}

bool ldif_comparision_objectSid_isString(const struct ldb_val *v)
{
	if (v->length < 3) {
		return false;
	}

	if (strncmp("S-", (const char *)v->data, 2) != 0) return false;
	
	return true;
}

/*
  compare two objectSids
*/
static int ldif_comparison_objectSid(struct ldb_context *ldb, void *mem_ctx,
				    const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (ldif_comparision_objectSid_isString(v1) && ldif_comparision_objectSid_isString(v2)) {
		return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
	} else if (ldif_comparision_objectSid_isString(v1)
		   && !ldif_comparision_objectSid_isString(v2)) {
		struct ldb_val v;
		int ret;
		if (ldif_read_objectSid(ldb, mem_ctx, v1, &v) != 0) {
			/* Perhaps not a string after all */
			return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
		}
		ret = ldb_comparison_binary(ldb, mem_ctx, &v, v2);
		talloc_free(v.data);
		return ret;
	} else if (!ldif_comparision_objectSid_isString(v1)
		   && ldif_comparision_objectSid_isString(v2)) {
		struct ldb_val v;
		int ret;
		if (ldif_read_objectSid(ldb, mem_ctx, v2, &v) != 0) {
			/* Perhaps not a string after all */
			return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
		}
		ret = ldb_comparison_binary(ldb, mem_ctx, v1, &v);
		talloc_free(v.data);
		return ret;
	}
	return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
}

/*
  canonicalise a objectSid
*/
static int ldif_canonicalise_objectSid(struct ldb_context *ldb, void *mem_ctx,
				      const struct ldb_val *in, struct ldb_val *out)
{
	if (ldif_comparision_objectSid_isString(in)) {
		if (ldif_read_objectSid(ldb, mem_ctx, in, out) != 0) {
			/* Perhaps not a string after all */
			return ldb_handler_copy(ldb, mem_ctx, in, out);
		}
		return 0;
	}
	return ldb_handler_copy(ldb, mem_ctx, in, out);
}

static int extended_dn_read_SID(struct ldb_context *ldb, void *mem_ctx,
			      const struct ldb_val *in, struct ldb_val *out)
{
	struct dom_sid sid;
	enum ndr_err_code ndr_err;
	if (ldif_comparision_objectSid_isString(in)) {
		if (ldif_read_objectSid(ldb, mem_ctx, in, out) == 0) {
			return 0;
		}
	}
	
	/* Perhaps not a string after all */
	*out = data_blob_talloc(mem_ctx, NULL, in->length/2+1);

	if (!out->data) {
		return -1;
	}

	(*out).length = strhex_to_str((char *)out->data, out->length,
				     (const char *)in->data, in->length);

	/* Check it looks like a SID */
	ndr_err = ndr_pull_struct_blob_all_noalloc(out, &sid,
					   (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}
	return 0;
}

/*
  convert a ldif formatted objectGUID to a NDR formatted blob
*/
static int ldif_read_objectGUID(struct ldb_context *ldb, void *mem_ctx,
			        const struct ldb_val *in, struct ldb_val *out)
{
	struct GUID guid;
	NTSTATUS status;

	status = GUID_from_data_blob(in, &guid);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	status = GUID_to_ndr_blob(&guid, mem_ctx, out);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return 0;
}

/*
  convert a NDR formatted blob to a ldif formatted objectGUID
*/
static int ldif_write_objectGUID(struct ldb_context *ldb, void *mem_ctx,
				 const struct ldb_val *in, struct ldb_val *out)
{
	struct GUID guid;
	NTSTATUS status;

	status = GUID_from_ndr_blob(in, &guid);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	out->data = (uint8_t *)GUID_string(mem_ctx, &guid);
	if (out->data == NULL) {
		return -1;
	}
	out->length = strlen((const char *)out->data);
	return 0;
}

static bool ldif_comparision_objectGUID_isString(const struct ldb_val *v)
{
	if (v->length != 36 && v->length != 38) return false;

	/* Might be a GUID string, can't be a binary GUID (fixed 16 bytes) */
	return true;
}

static int extended_dn_read_GUID(struct ldb_context *ldb, void *mem_ctx,
			      const struct ldb_val *in, struct ldb_val *out)
{

	if (in->length == 36 && ldif_read_objectGUID(ldb, mem_ctx, in, out) == 0) {
		return 0;
	}

	/* Try as 'hex' form */
	if (in->length != 32) {
		return -1;
	}
		
	*out = data_blob_talloc(mem_ctx, NULL, in->length/2+1);
	
	if (!out->data) {
		return -1;
	}
	
	(*out).length = strhex_to_str((char *)out->data, out->length,
				      (const char *)in->data, in->length);

	/* Check it looks like a GUID */
	if ((*out).length != 16) {
		data_blob_free(out);
		return -1;
	}

	return 0;
}

/*
  compare two objectGUIDs
*/
static int ldif_comparison_objectGUID(struct ldb_context *ldb, void *mem_ctx,
				     const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (ldif_comparision_objectGUID_isString(v1) && ldif_comparision_objectGUID_isString(v2)) {
		return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
	} else if (ldif_comparision_objectGUID_isString(v1)
		   && !ldif_comparision_objectGUID_isString(v2)) {
		struct ldb_val v;
		int ret;
		if (ldif_read_objectGUID(ldb, mem_ctx, v1, &v) != 0) {
			/* Perhaps it wasn't a valid string after all */
			return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
		}
		ret = ldb_comparison_binary(ldb, mem_ctx, &v, v2);
		talloc_free(v.data);
		return ret;
	} else if (!ldif_comparision_objectGUID_isString(v1)
		   && ldif_comparision_objectGUID_isString(v2)) {
		struct ldb_val v;
		int ret;
		if (ldif_read_objectGUID(ldb, mem_ctx, v2, &v) != 0) {
			/* Perhaps it wasn't a valid string after all */
			return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
		}
		ret = ldb_comparison_binary(ldb, mem_ctx, v1, &v);
		talloc_free(v.data);
		return ret;
	}
	return ldb_comparison_binary(ldb, mem_ctx, v1, v2);
}

/*
  canonicalise a objectGUID
*/
static int ldif_canonicalise_objectGUID(struct ldb_context *ldb, void *mem_ctx,
				       const struct ldb_val *in, struct ldb_val *out)
{
	if (ldif_comparision_objectGUID_isString(in)) {
		if (ldif_read_objectGUID(ldb, mem_ctx, in, out) != 0) {
			/* Perhaps it wasn't a valid string after all */
			return ldb_handler_copy(ldb, mem_ctx, in, out);
		}
		return 0;
	}
	return ldb_handler_copy(ldb, mem_ctx, in, out);
}


/*
  convert a ldif (SDDL) formatted ntSecurityDescriptor to a NDR formatted blob
*/
static int ldif_read_ntSecurityDescriptor(struct ldb_context *ldb, void *mem_ctx,
					  const struct ldb_val *in, struct ldb_val *out)
{
	struct security_descriptor *sd;
	enum ndr_err_code ndr_err;

	sd = talloc(mem_ctx, struct security_descriptor);
	if (sd == NULL) {
		return -1;
	}

	ndr_err = ndr_pull_struct_blob(in, sd, sd,
				       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		/* If this does not parse, then it is probably SDDL, and we should try it that way */

		const struct dom_sid *sid = samdb_domain_sid(ldb);
		talloc_free(sd);
		sd = sddl_decode(mem_ctx, (const char *)in->data, sid);
		if (sd == NULL) {
			return -1;
		}
	}

	ndr_err = ndr_push_struct_blob(out, mem_ctx, sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	talloc_free(sd);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}

	return 0;
}

/*
  convert a NDR formatted blob to a ldif formatted ntSecurityDescriptor (SDDL format)
*/
static int ldif_write_ntSecurityDescriptor(struct ldb_context *ldb, void *mem_ctx,
					   const struct ldb_val *in, struct ldb_val *out)
{
	struct security_descriptor *sd;
	enum ndr_err_code ndr_err;

	if (ldb_get_flags(ldb) & LDB_FLG_SHOW_BINARY) {
		return ldif_write_NDR(ldb, mem_ctx, in, out, 
				      sizeof(struct security_descriptor),
				      (ndr_pull_flags_fn_t)ndr_pull_security_descriptor,
				      (ndr_print_fn_t)ndr_print_security_descriptor,
				      true);
				      
	}

	sd = talloc(mem_ctx, struct security_descriptor);
	if (sd == NULL) {
		return -1;
	}
	/* We can't use ndr_pull_struct_blob_all because this contains relative pointers */
	ndr_err = ndr_pull_struct_blob(in, sd, sd,
					   (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(sd);
		return -1;
	}
	out->data = (uint8_t *)sddl_encode(mem_ctx, sd, samdb_domain_sid_cache_only(ldb));
	talloc_free(sd);
	if (out->data == NULL) {
		return -1;
	}
	out->length = strlen((const char *)out->data);
	return 0;
}

/*
  convert a string formatted SDDL to a ldif formatted ntSecurityDescriptor (SDDL format)
*/
static int ldif_write_sddlSecurityDescriptor(struct ldb_context *ldb, void *mem_ctx,
					   const struct ldb_val *in, struct ldb_val *out)
{
	if (ldb_get_flags(ldb) & LDB_FLG_SHOW_BINARY) {
		struct security_descriptor *sd;
		const struct dom_sid *sid = samdb_domain_sid(ldb);

		sd = sddl_decode(mem_ctx, (const char *)in->data, sid);
		out->data = (uint8_t *)ndr_print_struct_string(mem_ctx,
					(ndr_print_fn_t)ndr_print_security_descriptor,
					"SDDL", sd);
		out->length = strlen((const char *)out->data);
		talloc_free(sd);
		return 0;
	}

	return ldb_handler_copy(ldb, mem_ctx, in, out);
}

/* 
   canonicalise an objectCategory.  We use the long form as the canonical form:
   'person' becomes cn=Person,cn=Schema,cn=Configuration,<basedn>

   Also any short name of an objectClass that points to a different
   class (such as user) has the canonical form of the class it's
   defaultObjectCategory points to (eg
   cn=Person,cn=Schema,cn=Configuration,<basedn>)
*/

static int ldif_canonicalise_objectCategory(struct ldb_context *ldb, void *mem_ctx,
					    const struct ldb_val *in, struct ldb_val *out)
{
	struct ldb_dn *dn1 = NULL;
	const struct dsdb_schema *schema = dsdb_get_schema(ldb, NULL);
	const struct dsdb_class *sclass;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (!schema) {
		talloc_free(tmp_ctx);
		*out = data_blob_talloc(mem_ctx, in->data, in->length);
		if (in->data && !out->data) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		return LDB_SUCCESS;
	}
	dn1 = ldb_dn_from_ldb_val(tmp_ctx, ldb, in);
	if ( ! ldb_dn_validate(dn1)) {
		const char *lDAPDisplayName = talloc_strndup(tmp_ctx, (char *)in->data, in->length);
		sclass = dsdb_class_by_lDAPDisplayName(schema, lDAPDisplayName);
		if (sclass) {
			struct ldb_dn *dn = ldb_dn_new(tmp_ctx, ldb,
						       sclass->defaultObjectCategory);
			if (dn == NULL) {
				talloc_free(tmp_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			*out = data_blob_string_const(ldb_dn_alloc_casefold(mem_ctx, dn));
			talloc_free(tmp_ctx);

			if (!out->data) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
			return LDB_SUCCESS;
		} else {
			*out = data_blob_talloc(mem_ctx, in->data, in->length);
			talloc_free(tmp_ctx);

			if (in->data && !out->data) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
			return LDB_SUCCESS;
		}
	}
	*out = data_blob_string_const(ldb_dn_alloc_casefold(mem_ctx, dn1));
	talloc_free(tmp_ctx);

	if (!out->data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return LDB_SUCCESS;
}

static int ldif_comparison_objectCategory(struct ldb_context *ldb, void *mem_ctx,
					  const struct ldb_val *v1,
					  const struct ldb_val *v2)
{
	return ldb_any_comparison(ldb, mem_ctx, ldif_canonicalise_objectCategory,
				  v1, v2);
}

/*
  convert a NDR formatted blob to a ldif formatted schemaInfo
*/
static int ldif_write_schemaInfo(struct ldb_context *ldb, void *mem_ctx,
				 const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct repsFromToBlob),
			      (ndr_pull_flags_fn_t)ndr_pull_schemaInfoBlob,
			      (ndr_print_fn_t)ndr_print_schemaInfoBlob,
			      true);
}

/*
  convert a ldif formatted prefixMap to a NDR formatted blob
*/
static int ldif_read_prefixMap(struct ldb_context *ldb, void *mem_ctx,
			       const struct ldb_val *in, struct ldb_val *out)
{
	struct prefixMapBlob *blob;
	enum ndr_err_code ndr_err;
	char *string, *line, *p, *oid;
	DATA_BLOB oid_blob;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (tmp_ctx == NULL) {
		return -1;
	}

	blob = talloc_zero(tmp_ctx, struct prefixMapBlob);
	if (blob == NULL) {
		talloc_free(tmp_ctx);
		return -1;
	}

	/* use the switch value to detect if this is in the binary
	 * format
	 */
	if (in->length >= 4 && IVAL(in->data, 0) == PREFIX_MAP_VERSION_DSDB) {
		ndr_err = ndr_pull_struct_blob(in, tmp_ctx, blob,
					       (ndr_pull_flags_fn_t)ndr_pull_prefixMapBlob);
		if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			ndr_err = ndr_push_struct_blob(out, mem_ctx,
						       blob,
						       (ndr_push_flags_fn_t)ndr_push_prefixMapBlob);
			talloc_free(tmp_ctx);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return -1;
			}
			return 0;
		}
	}

	/* If this does not parse, then it is probably the text version, and we should try it that way */
	blob->version = PREFIX_MAP_VERSION_DSDB;
	
	string = talloc_strndup(mem_ctx, (const char *)in->data, in->length);
	if (string == NULL) {
		talloc_free(blob);
		return -1;
	}

	line = string;
	while (line && line[0]) {
		p=strchr(line, ';');
		if (p) {
			p[0] = '\0';
		} else {
			p=strchr(line, '\n');
			if (p) {
				p[0] = '\0';
			}
		}
		/* allow a trailing separator */
		if (line == p) {
			break;
		}
		
		blob->ctr.dsdb.mappings = talloc_realloc(blob, 
							 blob->ctr.dsdb.mappings, 
							 struct drsuapi_DsReplicaOIDMapping,
							 blob->ctr.dsdb.num_mappings+1);
		if (!blob->ctr.dsdb.mappings) {
			talloc_free(tmp_ctx);
			return -1;
		}

		blob->ctr.dsdb.mappings[blob->ctr.dsdb.num_mappings].id_prefix = strtoul(line, &oid, 10);

		if (oid[0] != ':') {
			talloc_free(tmp_ctx);
			return -1;
		}

		/* we know there must be at least ":" */
		oid++;

		if (!ber_write_partial_OID_String(blob->ctr.dsdb.mappings, &oid_blob, oid)) {
			talloc_free(tmp_ctx);
			return -1;
		}
		blob->ctr.dsdb.mappings[blob->ctr.dsdb.num_mappings].oid.length = oid_blob.length;
		blob->ctr.dsdb.mappings[blob->ctr.dsdb.num_mappings].oid.binary_oid = oid_blob.data;

		blob->ctr.dsdb.num_mappings++;

		/* Now look past the terminator we added above */
		if (p) {
			line = p + 1;
		} else {
			line = NULL;
		}
	}

	ndr_err = ndr_push_struct_blob(out, mem_ctx, 
				       blob,
				       (ndr_push_flags_fn_t)ndr_push_prefixMapBlob);
	talloc_free(tmp_ctx);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}
	return 0;
}

/*
  convert a NDR formatted blob to a ldif formatted prefixMap
*/
static int ldif_write_prefixMap(struct ldb_context *ldb, void *mem_ctx,
				const struct ldb_val *in, struct ldb_val *out)
{
	struct prefixMapBlob *blob;
	enum ndr_err_code ndr_err;
	char *string;
	uint32_t i;

	if (ldb_get_flags(ldb) & LDB_FLG_SHOW_BINARY) {
		int err;
		/* try to decode the blob as S4 prefixMap */
		err = ldif_write_NDR(ldb, mem_ctx, in, out,
		                     sizeof(struct prefixMapBlob),
		                     (ndr_pull_flags_fn_t)ndr_pull_prefixMapBlob,
		                     (ndr_print_fn_t)ndr_print_prefixMapBlob,
		                     false);
		if (0 == err) {
			return err;
		}
		/* try parsing it as Windows PrefixMap value */
		return ldif_write_NDR(ldb, mem_ctx, in, out,
		                      sizeof(struct drsuapi_MSPrefixMap_Ctr),
		                      (ndr_pull_flags_fn_t)ndr_pull_drsuapi_MSPrefixMap_Ctr,
		                      (ndr_print_fn_t)ndr_print_drsuapi_MSPrefixMap_Ctr,
		                      true);
	}

	blob = talloc(mem_ctx, struct prefixMapBlob);
	if (blob == NULL) {
		return -1;
	}
	ndr_err = ndr_pull_struct_blob_all(in, blob, 
					   blob,
					   (ndr_pull_flags_fn_t)ndr_pull_prefixMapBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto failed;
	}
	if (blob->version != PREFIX_MAP_VERSION_DSDB) {
		goto failed;
	}
	string = talloc_strdup(mem_ctx, "");
	if (string == NULL) {
		goto failed;
	}

	for (i=0; i < blob->ctr.dsdb.num_mappings; i++) {
		DATA_BLOB oid_blob;
		char *partial_oid = NULL;

		if (i > 0) {
			string = talloc_asprintf_append(string, ";"); 
		}

		oid_blob = data_blob_const(blob->ctr.dsdb.mappings[i].oid.binary_oid,
					   blob->ctr.dsdb.mappings[i].oid.length);
		if (!ber_read_partial_OID_String(blob, oid_blob, &partial_oid)) {
			DEBUG(0, ("ber_read_partial_OID failed on prefixMap item with id: 0x%X",
				  blob->ctr.dsdb.mappings[i].id_prefix));
			goto failed;
		}
		string = talloc_asprintf_append(string, "%u:%s", 
						   blob->ctr.dsdb.mappings[i].id_prefix,
						   partial_oid);
		talloc_free(discard_const(partial_oid));
		if (string == NULL) {
			goto failed;
		}
	}

	talloc_free(blob);
	*out = data_blob_string_const(string);
	return 0;

failed:
	talloc_free(blob);
	return -1;
}

static bool ldif_comparision_prefixMap_isString(const struct ldb_val *v)
{
	if (v->length < 4) {
		return true;
	}

	if (IVAL(v->data, 0) == PREFIX_MAP_VERSION_DSDB) {
		return false;
	}
	
	return true;
}

/*
  canonicalise a prefixMap
*/
static int ldif_canonicalise_prefixMap(struct ldb_context *ldb, void *mem_ctx,
				       const struct ldb_val *in, struct ldb_val *out)
{
	if (ldif_comparision_prefixMap_isString(in)) {
		return ldif_read_prefixMap(ldb, mem_ctx, in, out);
	}
	return ldb_handler_copy(ldb, mem_ctx, in, out);
}

static int ldif_comparison_prefixMap(struct ldb_context *ldb, void *mem_ctx,
				     const struct ldb_val *v1,
				     const struct ldb_val *v2)
{
	return ldb_any_comparison(ldb, mem_ctx, ldif_canonicalise_prefixMap,
				  v1, v2);
}

/* length limited conversion of a ldb_val to a int32_t */
static int val_to_int32(const struct ldb_val *in, int32_t *v)
{
	char *end;
	char buf[64];

	/* make sure we don't read past the end of the data */
	if (in->length > sizeof(buf)-1) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	strncpy(buf, (char *)in->data, in->length);
	buf[in->length] = 0;

	/* We've to use "strtoll" here to have the intended overflows.
	 * Otherwise we may get "LONG_MAX" and the conversion is wrong. */
	*v = (int32_t) strtoll(buf, &end, 0);
	if (*end != 0) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	return LDB_SUCCESS;
}

/* length limited conversion of a ldb_val to a int64_t */
static int val_to_int64(const struct ldb_val *in, int64_t *v)
{
	char *end;
	char buf[64];

	/* make sure we don't read past the end of the data */
	if (in->length > sizeof(buf)-1) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	strncpy(buf, (char *)in->data, in->length);
	buf[in->length] = 0;

	*v = (int64_t) strtoll(buf, &end, 0);
	if (*end != 0) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	return LDB_SUCCESS;
}

/* Canonicalisation of two 32-bit integers */
static int ldif_canonicalise_int32(struct ldb_context *ldb, void *mem_ctx,
			const struct ldb_val *in, struct ldb_val *out)
{
	int32_t i;
	int ret;

	ret = val_to_int32(in, &i);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	out->data = (uint8_t *) talloc_asprintf(mem_ctx, "%d", i);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	out->length = strlen((char *)out->data);
	return 0;
}

/* Comparison of two 32-bit integers */
static int ldif_comparison_int32(struct ldb_context *ldb, void *mem_ctx,
				 const struct ldb_val *v1, const struct ldb_val *v2)
{
	int32_t i1=0, i2=0;
	val_to_int32(v1, &i1);
	val_to_int32(v2, &i2);
	if (i1 == i2) return 0;
	return i1 > i2? 1 : -1;
}

/* Canonicalisation of two 64-bit integers */
static int ldif_canonicalise_int64(struct ldb_context *ldb, void *mem_ctx,
				   const struct ldb_val *in, struct ldb_val *out)
{
	int64_t i;
	int ret;

	ret = val_to_int64(in, &i);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	out->data = (uint8_t *) talloc_asprintf(mem_ctx, "%lld", (long long)i);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	out->length = strlen((char *)out->data);
	return 0;
}

/* Comparison of two 64-bit integers */
static int ldif_comparison_int64(struct ldb_context *ldb, void *mem_ctx,
				 const struct ldb_val *v1, const struct ldb_val *v2)
{
	int64_t i1=0, i2=0;
	val_to_int64(v1, &i1);
	val_to_int64(v2, &i2);
	if (i1 == i2) return 0;
	return i1 > i2? 1 : -1;
}

/*
  convert a NDR formatted blob to a ldif formatted repsFromTo
*/
static int ldif_write_repsFromTo(struct ldb_context *ldb, void *mem_ctx,
				 const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out, 
			      sizeof(struct repsFromToBlob),
			      (ndr_pull_flags_fn_t)ndr_pull_repsFromToBlob,
			      (ndr_print_fn_t)ndr_print_repsFromToBlob,
			      true);
}

/*
  convert a NDR formatted blob to a ldif formatted replPropertyMetaData
*/
static int ldif_write_replPropertyMetaData(struct ldb_context *ldb, void *mem_ctx,
					   const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out, 
			      sizeof(struct replPropertyMetaDataBlob),
			      (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob,
			      (ndr_print_fn_t)ndr_print_replPropertyMetaDataBlob,
			      true);
}

/*
  convert a NDR formatted blob to a ldif formatted replUpToDateVector
*/
static int ldif_write_replUpToDateVector(struct ldb_context *ldb, void *mem_ctx,
					 const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out, 
			      sizeof(struct replUpToDateVectorBlob),
			      (ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob,
			      (ndr_print_fn_t)ndr_print_replUpToDateVectorBlob,
			      true);
}

static int ldif_write_dn_binary_NDR(struct ldb_context *ldb, void *mem_ctx,
				    const struct ldb_val *in, struct ldb_val *out,
				    size_t struct_size,
				    ndr_pull_flags_fn_t pull_fn,
				    ndr_print_fn_t print_fn,
				    bool mask_errors)
{
	uint8_t *p = NULL;
	enum ndr_err_code err;
	struct dsdb_dn *dsdb_dn = NULL;
	char *dn_str = NULL;
	char *str = NULL;

	if (!(ldb_get_flags(ldb) & LDB_FLG_SHOW_BINARY)) {
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}

	dsdb_dn = dsdb_dn_parse(mem_ctx, ldb, in, DSDB_SYNTAX_BINARY_DN);
	if (dsdb_dn == NULL) {
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}

	p = talloc_size(dsdb_dn, struct_size);
	if (p == NULL) {
		TALLOC_FREE(dsdb_dn);
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}

	err = ndr_pull_struct_blob(&dsdb_dn->extra_part, p, p, pull_fn);
	if (err != NDR_ERR_SUCCESS) {
		/* fail in not in mask_error mode */
		if (!mask_errors) {
			return -1;
		}
		TALLOC_FREE(dsdb_dn);
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}

	dn_str = ldb_dn_get_extended_linearized(dsdb_dn, dsdb_dn->dn, 1);
	if (dn_str == NULL) {
		TALLOC_FREE(dsdb_dn);
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}

	str = ndr_print_struct_string(mem_ctx, print_fn, dn_str, p);
	TALLOC_FREE(dsdb_dn);
	if (str == NULL) {
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}

	*out = data_blob_string_const(str);
	return 0;
}

static int ldif_write_msDS_RevealedUsers(struct ldb_context *ldb, void *mem_ctx,
					 const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_dn_binary_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct replPropertyMetaData1),
			      (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaData1,
			      (ndr_print_fn_t)ndr_print_replPropertyMetaData1,
			      true);
}

/*
  convert a NDR formatted blob to a ldif formatted dnsRecord
*/
static int ldif_write_dnsRecord(struct ldb_context *ldb, void *mem_ctx,
				const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct dnsp_DnssrvRpcRecord),
			      (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord,
			      (ndr_print_fn_t)ndr_print_dnsp_DnssrvRpcRecord,
			      true);
}

/*
  convert a NDR formatted blob to a ldif formatted dnsProperty
*/
static int ldif_write_dnsProperty(struct ldb_context *ldb, void *mem_ctx,
				const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct dnsp_DnsProperty),
			      (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnsProperty,
			      (ndr_print_fn_t)ndr_print_dnsp_DnsProperty,
			      true);
}

/*
  convert a NDR formatted blob of a supplementalCredentials into text
*/
static int ldif_write_supplementalCredentialsBlob(struct ldb_context *ldb, void *mem_ctx,
						  const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct supplementalCredentialsBlob),
			      (ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob,
			      (ndr_print_fn_t)ndr_print_supplementalCredentialsBlob,
			      true);
}

/*
  convert a NDR formatted blob to a ldif formatted trustAuthInOutBlob
*/
static int ldif_write_trustAuthInOutBlob(struct ldb_context *ldb, void *mem_ctx,
					   const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct trustAuthInOutBlob),
			      (ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob,
			      (ndr_print_fn_t)ndr_print_trustAuthInOutBlob,
			      true);
}

/*
  convert a NDR formatted blob to a ldif formatted msDS-TrustForestTrustInfo
*/
static int ldif_write_ForestTrustInfo(struct ldb_context *ldb, void *mem_ctx,
				      const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct ForestTrustInfo),
			      (ndr_pull_flags_fn_t)ndr_pull_ForestTrustInfo,
			      (ndr_print_fn_t)ndr_print_ForestTrustInfo,
			      true);
}
/*
  convert a NDR formatted blob of a partialAttributeSet into text
*/
static int ldif_write_partialAttributeSet(struct ldb_context *ldb, void *mem_ctx,
					  const struct ldb_val *in, struct ldb_val *out)
{
	return ldif_write_NDR(ldb, mem_ctx, in, out,
			      sizeof(struct partialAttributeSetBlob),
			      (ndr_pull_flags_fn_t)ndr_pull_partialAttributeSetBlob,
			      (ndr_print_fn_t)ndr_print_partialAttributeSetBlob,
			      true);
}


static int extended_dn_write_hex(struct ldb_context *ldb, void *mem_ctx,
				 const struct ldb_val *in, struct ldb_val *out)
{
	*out = data_blob_string_const(data_blob_hex_string_lower(mem_ctx, in));
	if (!out->data) {
		return -1;
	}
	return 0;
}

/*
  compare two dns
*/
static int samba_ldb_dn_link_comparison(struct ldb_context *ldb, void *mem_ctx,
					const struct ldb_val *v1, const struct ldb_val *v2)
{
	struct ldb_dn *dn1 = NULL, *dn2 = NULL;
	int ret;

	if (dsdb_dn_is_deleted_val(v1)) {
		/* If the DN is deleted, then we can't search for it */
		return -1;
	}

	if (dsdb_dn_is_deleted_val(v2)) {
		/* If the DN is deleted, then we can't search for it */
		return -1;
	}

	dn1 = ldb_dn_from_ldb_val(mem_ctx, ldb, v1);
	if ( ! ldb_dn_validate(dn1)) return -1;

	dn2 = ldb_dn_from_ldb_val(mem_ctx, ldb, v2);
	if ( ! ldb_dn_validate(dn2)) {
		talloc_free(dn1);
		return -1;
	}

	ret = ldb_dn_compare(dn1, dn2);

	talloc_free(dn1);
	talloc_free(dn2);
	return ret;
}

static int samba_ldb_dn_link_canonicalise(struct ldb_context *ldb, void *mem_ctx,
					  const struct ldb_val *in, struct ldb_val *out)
{
	struct ldb_dn *dn;
	int ret = -1;

	out->length = 0;
	out->data = NULL;

	dn = ldb_dn_from_ldb_val(mem_ctx, ldb, in);
	if ( ! ldb_dn_validate(dn)) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	/* By including the RMD_FLAGS of a deleted DN, we ensure it
	 * does not casually match a not deleted DN */
	if (dsdb_dn_is_deleted_val(in)) {
		out->data = (uint8_t *)talloc_asprintf(mem_ctx,
						       "<RMD_FLAGS=%u>%s",
						       dsdb_dn_val_rmd_flags(in),
						       ldb_dn_get_casefold(dn));
	} else {
		out->data = (uint8_t *)ldb_dn_alloc_casefold(mem_ctx, dn);
	}

	if (out->data == NULL) {
		goto done;
	}
	out->length = strlen((char *)out->data);

	ret = 0;

done:
	talloc_free(dn);

	return ret;
}


/*
  write a 64 bit 2-part range
*/
static int ldif_write_range64(struct ldb_context *ldb, void *mem_ctx,
			      const struct ldb_val *in, struct ldb_val *out)
{
	int64_t v;
	int ret;
	ret = val_to_int64(in, &v);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	out->data = (uint8_t *)talloc_asprintf(mem_ctx, "%lu-%lu",
					       (unsigned long)(v&0xFFFFFFFF),
					       (unsigned long)(v>>32));
	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	out->length = strlen((char *)out->data);
	return LDB_SUCCESS;
}

/*
  read a 64 bit 2-part range
*/
static int ldif_read_range64(struct ldb_context *ldb, void *mem_ctx,
			      const struct ldb_val *in, struct ldb_val *out)
{
	unsigned long high, low;
	char buf[64];

	if (memchr(in->data, '-', in->length) == NULL) {
		return ldb_handler_copy(ldb, mem_ctx, in, out);
	}

	if (in->length > sizeof(buf)-1) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	strncpy(buf, (const char *)in->data, in->length);
	buf[in->length] = 0;

	if (sscanf(buf, "%lu-%lu", &low, &high) != 2) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	out->data = (uint8_t *)talloc_asprintf(mem_ctx, "%llu",
					       (unsigned long long)(((uint64_t)high)<<32) | (low));

	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	out->length = strlen((char *)out->data);
	return LDB_SUCCESS;
}

/*
  when this operator_fn is set for a syntax, the backend calls is in
  preference to the comparison function. We are told the exact
  comparison operation that is needed, and we can return errors
 */
static int samba_syntax_operator_fn(struct ldb_context *ldb, enum ldb_parse_op operation,
				    const struct ldb_schema_attribute *a,
				    const struct ldb_val *v1, const struct ldb_val *v2, bool *matched)
{
	switch (operation) {
	case LDB_OP_AND:
	case LDB_OP_OR:
	case LDB_OP_NOT:
	case LDB_OP_SUBSTRING:
	case LDB_OP_APPROX:
	case LDB_OP_EXTENDED:
		/* handled in the backends */
		return LDB_ERR_INAPPROPRIATE_MATCHING;

	case LDB_OP_GREATER:
	case LDB_OP_LESS:
	case LDB_OP_EQUALITY:
	{
		TALLOC_CTX *tmp_ctx = talloc_new(ldb);
		int ret;
		if (tmp_ctx == NULL) {
			return ldb_oom(ldb);
		}
		ret = a->syntax->comparison_fn(ldb, tmp_ctx, v1, v2);
		talloc_free(tmp_ctx);
		if (operation == LDB_OP_GREATER) {
			*matched = (ret >= 0);
		} else if (operation == LDB_OP_LESS) {
			*matched = (ret <= 0);
		} else {
			*matched = (ret == 0);
		}
		return LDB_SUCCESS;
	}

	case LDB_OP_PRESENT:
		*matched = true;
		return LDB_SUCCESS;
	}

	/* we shouldn't get here */
	return LDB_ERR_INAPPROPRIATE_MATCHING;
}

/*
  compare two binary objects.  This is correct for sorting as the sort order is:
  
  a
  aa
  b
  bb

  rather than ldb_comparison_binary() which is:

  a
  b
  aa
  bb
  
*/
static int samba_ldb_comparison_binary(struct ldb_context *ldb, void *mem_ctx,
				       const struct ldb_val *v1, const struct ldb_val *v2)
{
	return data_blob_cmp(v1, v2);
}

/*
  when this operator_fn is set for a syntax, the backend calls is in
  preference to the comparison function. We are told the exact
  comparison operation that is needed, and we can return errors.

  This mode optimises for ldb_comparison_binary() if we need equality,
  as this should be faster as it can do a length-check first.
 */
static int samba_syntax_binary_operator_fn(struct ldb_context *ldb, enum ldb_parse_op operation,
					   const struct ldb_schema_attribute *a,
					   const struct ldb_val *v1, const struct ldb_val *v2, bool *matched)
{
	if (operation == LDB_OP_EQUALITY) {
		*matched = (ldb_comparison_binary(ldb, NULL, v1, v2) == 0);
		return LDB_SUCCESS;
	}
	return samba_syntax_operator_fn(ldb, operation, a, v1, v2, matched);
}

/*
  see if two DNs match, comparing first by GUID, then by SID, and
  finally by string components
 */
static int samba_dn_extended_match(struct ldb_context *ldb,
				   const struct ldb_val *v1,
				   const struct ldb_val *v2,
				   bool *matched)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *dn1, *dn2;
	const struct ldb_val *guid1, *guid2, *sid1, *sid2;
	uint32_t rmd_flags1, rmd_flags2;

	tmp_ctx = talloc_new(ldb);

	dn1 = ldb_dn_from_ldb_val(tmp_ctx, ldb, v1);
	dn2 = ldb_dn_from_ldb_val(tmp_ctx, ldb, v2);
	if (!dn1 || !dn2) {
		/* couldn't parse as DN's */
		talloc_free(tmp_ctx);
		(*matched) = false;
		return LDB_SUCCESS;
	}

	rmd_flags1 = dsdb_dn_rmd_flags(dn1);
	rmd_flags2 = dsdb_dn_rmd_flags(dn2);

	if ((rmd_flags1 & DSDB_RMD_FLAG_DELETED) !=
	    (rmd_flags2 & DSDB_RMD_FLAG_DELETED)) {
		/* only match if they have the same deletion status */
		talloc_free(tmp_ctx);
		(*matched) = false;
		return LDB_SUCCESS;
	}


	guid1 = ldb_dn_get_extended_component(dn1, "GUID");
	guid2 = ldb_dn_get_extended_component(dn2, "GUID");
	if (guid1 && guid2) {
		(*matched) = (data_blob_cmp(guid1, guid2) == 0);
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	sid1 = ldb_dn_get_extended_component(dn1, "SID");
	sid2 = ldb_dn_get_extended_component(dn2, "SID");
	if (sid1 && sid2) {
		(*matched) = (data_blob_cmp(sid1, sid2) == 0);
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	(*matched) = (ldb_dn_compare(dn1, dn2) == 0);

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

/*
  special operation for DNs, to take account of the RMD_FLAGS deleted bit
 */
static int samba_syntax_operator_dn(struct ldb_context *ldb, enum ldb_parse_op operation,
				    const struct ldb_schema_attribute *a,
				    const struct ldb_val *v1, const struct ldb_val *v2, bool *matched)
{
	if (operation == LDB_OP_PRESENT && dsdb_dn_is_deleted_val(v1)) {
		/* If the DN is deleted, then we can't search for it */

		/* should this be for equality too? */
		*matched = false;
		return LDB_SUCCESS;
	}

	if (operation == LDB_OP_EQUALITY &&
	    samba_dn_extended_match(ldb, v1, v2, matched) == LDB_SUCCESS) {
		return LDB_SUCCESS;
	}

	return samba_syntax_operator_fn(ldb, operation, a, v1, v2, matched);
}


static const struct ldb_schema_syntax samba_syntaxes[] = {
	{
		.name		  = LDB_SYNTAX_SAMBA_SID,
		.ldif_read_fn	  = ldif_read_objectSid,
		.ldif_write_fn	  = ldif_write_objectSid,
		.canonicalise_fn  = ldif_canonicalise_objectSid,
		.comparison_fn	  = ldif_comparison_objectSid,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_SECURITY_DESCRIPTOR,
		.ldif_read_fn	  = ldif_read_ntSecurityDescriptor,
		.ldif_write_fn	  = ldif_write_ntSecurityDescriptor,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_SDDL_SECURITY_DESCRIPTOR,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_sddlSecurityDescriptor,
		.canonicalise_fn  = ldb_handler_fold,
		.comparison_fn	  = ldb_comparison_fold,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_GUID,
		.ldif_read_fn	  = ldif_read_objectGUID,
		.ldif_write_fn	  = ldif_write_objectGUID,
		.canonicalise_fn  = ldif_canonicalise_objectGUID,
		.comparison_fn	  = ldif_comparison_objectGUID,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_OBJECT_CATEGORY,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldb_handler_copy,
		.canonicalise_fn  = ldif_canonicalise_objectCategory,
		.comparison_fn	  = ldif_comparison_objectCategory,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_SCHEMAINFO,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_schemaInfo,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_PREFIX_MAP,
		.ldif_read_fn	  = ldif_read_prefixMap,
		.ldif_write_fn	  = ldif_write_prefixMap,
		.canonicalise_fn  = ldif_canonicalise_prefixMap,
		.comparison_fn	  = ldif_comparison_prefixMap,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_INT32,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldb_handler_copy,
		.canonicalise_fn  = ldif_canonicalise_int32,
		.comparison_fn	  = ldif_comparison_int32,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_REPSFROMTO,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_repsFromTo,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_REPLPROPERTYMETADATA,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_replPropertyMetaData,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_REPLUPTODATEVECTOR,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_replUpToDateVector,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_REVEALEDUSERS,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_msDS_RevealedUsers,
		.canonicalise_fn  = dsdb_dn_binary_canonicalise,
		.comparison_fn	  = dsdb_dn_binary_comparison,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_TRUSTAUTHINOUTBLOB,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_trustAuthInOutBlob,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_FORESTTRUSTINFO,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_ForestTrustInfo,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = DSDB_SYNTAX_BINARY_DN,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldb_handler_copy,
		.canonicalise_fn  = dsdb_dn_binary_canonicalise,
		.comparison_fn	  = dsdb_dn_binary_comparison,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = DSDB_SYNTAX_STRING_DN,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldb_handler_copy,
		.canonicalise_fn  = dsdb_dn_string_canonicalise,
		.comparison_fn	  = dsdb_dn_string_comparison,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_DN,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldb_handler_copy,
		.canonicalise_fn  = samba_ldb_dn_link_canonicalise,
		.comparison_fn	  = samba_ldb_dn_link_comparison,
		.operator_fn      = samba_syntax_operator_dn
	},{
		.name		  = LDB_SYNTAX_SAMBA_RANGE64,
		.ldif_read_fn	  = ldif_read_range64,
		.ldif_write_fn	  = ldif_write_range64,
		.canonicalise_fn  = ldif_canonicalise_int64,
		.comparison_fn	  = ldif_comparison_int64,
		.operator_fn      = samba_syntax_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_DNSRECORD,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_dnsRecord,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_DNSPROPERTY,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_dnsProperty,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_SUPPLEMENTALCREDENTIALS,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_supplementalCredentialsBlob,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_PARTIALATTRIBUTESET,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldif_write_partialAttributeSet,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	},{
		.name		  = LDB_SYNTAX_SAMBA_OCTET_STRING,
		.ldif_read_fn	  = ldb_handler_copy,
		.ldif_write_fn	  = ldb_handler_copy,
		.canonicalise_fn  = ldb_handler_copy,
		.comparison_fn	  = samba_ldb_comparison_binary,
		.operator_fn      = samba_syntax_binary_operator_fn
	}
};

static const struct ldb_dn_extended_syntax samba_dn_syntax[] = {
	{
		.name		  = "SID",
		.read_fn          = extended_dn_read_SID,
		.write_clear_fn   = ldif_write_objectSid,
		.write_hex_fn     = extended_dn_write_hex
	},{
		.name		  = "GUID",
		.read_fn          = extended_dn_read_GUID,
		.write_clear_fn   = ldif_write_objectGUID,
		.write_hex_fn     = extended_dn_write_hex
	},{
		.name		  = "WKGUID",
		.read_fn          = ldb_handler_copy,
		.write_clear_fn   = ldb_handler_copy,
		.write_hex_fn     = ldb_handler_copy
	},{
		.name		  = "RMD_INVOCID",
		.read_fn          = extended_dn_read_GUID,
		.write_clear_fn   = ldif_write_objectGUID,
		.write_hex_fn     = extended_dn_write_hex
	},{
		.name		  = "RMD_FLAGS",
		.read_fn          = ldb_handler_copy,
		.write_clear_fn   = ldb_handler_copy,
		.write_hex_fn     = ldb_handler_copy
	},{
		.name		  = "RMD_ADDTIME",
		.read_fn          = ldb_handler_copy,
		.write_clear_fn   = ldb_handler_copy,
		.write_hex_fn     = ldb_handler_copy
	},{
		.name		  = "RMD_CHANGETIME",
		.read_fn          = ldb_handler_copy,
		.write_clear_fn   = ldb_handler_copy,
		.write_hex_fn     = ldb_handler_copy
	},{
		.name		  = "RMD_LOCAL_USN",
		.read_fn          = ldb_handler_copy,
		.write_clear_fn   = ldb_handler_copy,
		.write_hex_fn     = ldb_handler_copy
	},{
		.name		  = "RMD_ORIGINATING_USN",
		.read_fn          = ldb_handler_copy,
		.write_clear_fn   = ldb_handler_copy,
		.write_hex_fn     = ldb_handler_copy
	},{
		.name		  = "RMD_VERSION",
		.read_fn          = ldb_handler_copy,
		.write_clear_fn   = ldb_handler_copy,
		.write_hex_fn     = ldb_handler_copy
	}
};

/* TODO: Should be dynamic at some point */
static const struct {
	const char *name;
	const char *syntax;
} samba_attributes[] = {
	{ "ntSecurityDescriptor",	LDB_SYNTAX_SAMBA_SECURITY_DESCRIPTOR },
	{ "oMSyntax",			LDB_SYNTAX_SAMBA_INT32 },
	{ "objectCategory",		LDB_SYNTAX_SAMBA_OBJECT_CATEGORY },
	{ "schemaInfo",			LDB_SYNTAX_SAMBA_SCHEMAINFO },
	{ "prefixMap",                  LDB_SYNTAX_SAMBA_PREFIX_MAP },
	{ "repsFrom",                   LDB_SYNTAX_SAMBA_REPSFROMTO },
	{ "repsTo",                     LDB_SYNTAX_SAMBA_REPSFROMTO },
	{ "replPropertyMetaData",       LDB_SYNTAX_SAMBA_REPLPROPERTYMETADATA },
	{ "replUpToDateVector",         LDB_SYNTAX_SAMBA_REPLUPTODATEVECTOR },
	{ "msDS-RevealedUsers",         LDB_SYNTAX_SAMBA_REVEALEDUSERS },
	{ "trustAuthIncoming",          LDB_SYNTAX_SAMBA_TRUSTAUTHINOUTBLOB },
	{ "trustAuthOutgoing",          LDB_SYNTAX_SAMBA_TRUSTAUTHINOUTBLOB },
	{ "msDS-TrustForestTrustInfo",  LDB_SYNTAX_SAMBA_FORESTTRUSTINFO },
	{ "rIDAllocationPool",		LDB_SYNTAX_SAMBA_RANGE64 },
	{ "rIDPreviousAllocationPool",	LDB_SYNTAX_SAMBA_RANGE64 },
	{ "rIDAvailablePool",		LDB_SYNTAX_SAMBA_RANGE64 },
	{ "defaultSecurityDescriptor",	LDB_SYNTAX_SAMBA_SDDL_SECURITY_DESCRIPTOR },

	/*
	 * these are extracted by searching
	 * (&(attributeSyntax=2.5.5.17)(omSyntax=4))
	 *
	 * Except: msAuthz-CentralAccessPolicyID as it might be a GUID see:
	 * adminDescription: For a Central Access Policy, this attribute defines a GUID t
	 * hat can be used to identify the set of policies when applied to a resource.
	 * Until we see a msAuthz-CentralAccessPolicyID value on a windows
	 * server, we ignore it here.
	 */
	{ "mS-DS-CreatorSID",		LDB_SYNTAX_SAMBA_SID },
	{ "msDS-QuotaTrustee",		LDB_SYNTAX_SAMBA_SID },
	{ "objectSid",			LDB_SYNTAX_SAMBA_SID },
	{ "tokenGroups", 	        LDB_SYNTAX_SAMBA_SID },
	{ "tokenGroupsGlobalAndUniversal", LDB_SYNTAX_SAMBA_SID },
	{ "tokenGroupsNoGCAcceptable",  LDB_SYNTAX_SAMBA_SID },
	{ "securityIdentifier", 	LDB_SYNTAX_SAMBA_SID },
	{ "sIDHistory",			LDB_SYNTAX_SAMBA_SID },
	{ "syncWithSID",		LDB_SYNTAX_SAMBA_SID },

	/*
	 * these are extracted by searching
	 * (&(attributeSyntax=2.5.5.10)(rangeLower=16)(rangeUpper=16)(omSyntax=4))
	 */
	{ "attributeSecurityGUID",		LDB_SYNTAX_SAMBA_GUID },
	{ "categoryId",				LDB_SYNTAX_SAMBA_GUID },
	{ "controlAccessRights",		LDB_SYNTAX_SAMBA_GUID },
	{ "currMachineId",			LDB_SYNTAX_SAMBA_GUID },
	{ "fRSReplicaSetGUID",			LDB_SYNTAX_SAMBA_GUID },
	{ "fRSVersionGUID",			LDB_SYNTAX_SAMBA_GUID },
	{ "implementedCategories",		LDB_SYNTAX_SAMBA_GUID },
	{ "msDS-AzObjectGuid",			LDB_SYNTAX_SAMBA_GUID },
	{ "msDS-GenerationId",			LDB_SYNTAX_SAMBA_GUID },
	{ "msDS-OptionalFeatureGUID",		LDB_SYNTAX_SAMBA_GUID },
	{ "msDFSR-ContentSetGuid",		LDB_SYNTAX_SAMBA_GUID },
	{ "msDFSR-ReplicationGroupGuid",	LDB_SYNTAX_SAMBA_GUID },
	{ "mSMQDigests",			LDB_SYNTAX_SAMBA_GUID },
	{ "mSMQOwnerID",			LDB_SYNTAX_SAMBA_GUID },
	{ "mSMQQMID",				LDB_SYNTAX_SAMBA_GUID },
	{ "mSMQQueueType",			LDB_SYNTAX_SAMBA_GUID },
	{ "mSMQSites",				LDB_SYNTAX_SAMBA_GUID },
	{ "netbootGUID",			LDB_SYNTAX_SAMBA_GUID },
	{ "objectGUID",				LDB_SYNTAX_SAMBA_GUID },
	{ "pKTGuid",				LDB_SYNTAX_SAMBA_GUID },
	{ "requiredCategories",			LDB_SYNTAX_SAMBA_GUID },
	{ "schemaIDGUID",			LDB_SYNTAX_SAMBA_GUID },
	{ "siteGUID",				LDB_SYNTAX_SAMBA_GUID },
	{ "msDFS-GenerationGUIDv2",		LDB_SYNTAX_SAMBA_GUID },
	{ "msDFS-LinkIdentityGUIDv2",		LDB_SYNTAX_SAMBA_GUID },
	{ "msDFS-NamespaceIdentityGUIDv2",	LDB_SYNTAX_SAMBA_GUID },
	{ "msSPP-CSVLKSkuId",			LDB_SYNTAX_SAMBA_GUID },
	{ "msSPP-KMSIds",			LDB_SYNTAX_SAMBA_GUID },

	/*
	 * these are known to be GUIDs
	 */
	{ "invocationId",			LDB_SYNTAX_SAMBA_GUID },
	{ "parentGUID",				LDB_SYNTAX_SAMBA_GUID },

	/* These NDR encoded things we want to be able to read with --show-binary */
	{ "dnsRecord",				LDB_SYNTAX_SAMBA_DNSRECORD },
	{ "dNSProperty",			LDB_SYNTAX_SAMBA_DNSPROPERTY },
	{ "supplementalCredentials",		LDB_SYNTAX_SAMBA_SUPPLEMENTALCREDENTIALS},
	{ "partialAttributeSet",		LDB_SYNTAX_SAMBA_PARTIALATTRIBUTESET}
};

const struct ldb_schema_syntax *ldb_samba_syntax_by_name(struct ldb_context *ldb, const char *name)
{
	unsigned int j;
	const struct ldb_schema_syntax *s = NULL;
	
	for (j=0; j < ARRAY_SIZE(samba_syntaxes); j++) {
		if (strcmp(name, samba_syntaxes[j].name) == 0) {
			s = &samba_syntaxes[j];
			break;
		}
	}
	return s;
}

const struct ldb_schema_syntax *ldb_samba_syntax_by_lDAPDisplayName(struct ldb_context *ldb, const char *name)
{
	unsigned int j;
	const struct ldb_schema_syntax *s = NULL;

	for (j=0; j < ARRAY_SIZE(samba_attributes); j++) {
		if (strcmp(samba_attributes[j].name, name) == 0) {
			s = ldb_samba_syntax_by_name(ldb, samba_attributes[j].syntax);
			break;
		}
	}
	
	return s;
}

static const char *secret_attributes[] = {DSDB_SECRET_ATTRIBUTES, "secret", NULL};

/*
  register the samba ldif handlers
*/
int ldb_register_samba_handlers(struct ldb_context *ldb)
{
	unsigned int i;
	int ret;

	if (ldb_get_opaque(ldb, "SAMBA_HANDLERS_REGISTERED") != NULL) {
		return LDB_SUCCESS;
	}

	ret = ldb_set_opaque(ldb, LDB_SECRET_ATTRIBUTE_LIST_OPAQUE, discard_const_p(char *, secret_attributes));
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	for (i=0; i < ARRAY_SIZE(samba_attributes); i++) {
		const struct ldb_schema_syntax *s = NULL;

		s = ldb_samba_syntax_by_name(ldb, samba_attributes[i].syntax);

		if (!s) {
			s = ldb_standard_syntax_by_name(ldb, samba_attributes[i].syntax);
		}

		if (!s) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_schema_attribute_add_with_syntax(ldb, samba_attributes[i].name, LDB_ATTR_FLAG_FIXED, s);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	for (i=0; i < ARRAY_SIZE(samba_dn_syntax); i++) {
		ret = ldb_dn_extended_add_syntax(ldb, LDB_ATTR_FLAG_FIXED, &samba_dn_syntax[i]);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

	}

	ret = ldb_register_samba_matching_rules(ldb);
	if (ret != LDB_SUCCESS) {
		talloc_free(ldb);
		return LDB_SUCCESS;
	}

	ret = ldb_set_opaque(ldb, "SAMBA_HANDLERS_REGISTERED", (void*)1);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}
