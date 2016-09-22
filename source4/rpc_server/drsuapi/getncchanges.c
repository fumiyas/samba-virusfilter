/* 
   Unix SMB/CIFS implementation.

   implement the DSGetNCChanges call

   Copyright (C) Anatoliy Atanasov 2009
   Copyright (C) Andrew Tridgell 2009-2010
   Copyright (C) Andrew Bartlett 2010-2016

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
#include "rpc_server/dcerpc_server.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "libcli/security/session.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"
#include "rpc_server/dcerpc_server_proto.h"
#include "../libcli/drsuapi/drsuapi.h"
#include "lib/util/binsearch.h"
#include "lib/util/tsort.h"
#include "auth/session.h"
#include "dsdb/common/util.h"

/* state of a partially completed getncchanges call */
struct drsuapi_getncchanges_state {
	struct GUID *guids;
	uint32_t num_records;
	uint32_t num_processed;
	struct ldb_dn *ncRoot_dn;
	bool is_schema_nc;
	uint64_t min_usn;
	uint64_t max_usn;
	struct drsuapi_DsReplicaHighWaterMark last_hwm;
	struct ldb_dn *last_dn;
	struct drsuapi_DsReplicaHighWaterMark final_hwm;
	struct drsuapi_DsReplicaCursor2CtrEx *final_udv;
	struct drsuapi_DsReplicaLinkedAttribute *la_list;
	uint32_t la_count;
	struct la_for_sorting *la_sorted;
	uint32_t la_idx;
};

/* We must keep the GUIDs in NDR form for sorting */
struct la_for_sorting {
	struct drsuapi_DsReplicaLinkedAttribute *link;
	uint8_t target_guid[16];
        uint8_t source_guid[16];
};

static int drsuapi_DsReplicaHighWaterMark_cmp(const struct drsuapi_DsReplicaHighWaterMark *h1,
					      const struct drsuapi_DsReplicaHighWaterMark *h2)
{
	if (h1->highest_usn < h2->highest_usn) {
		return -1;
	} else if (h1->highest_usn > h2->highest_usn) {
		return 1;
	} else if (h1->tmp_highest_usn < h2->tmp_highest_usn) {
		return -1;
	} else if (h1->tmp_highest_usn > h2->tmp_highest_usn) {
		return 1;
	} else if (h1->reserved_usn < h2->reserved_usn) {
		return -1;
	} else if (h1->reserved_usn > h2->reserved_usn) {
		return 1;
	}

	return 0;
}

/*
  build a DsReplicaObjectIdentifier from a ldb msg
 */
static struct drsuapi_DsReplicaObjectIdentifier *get_object_identifier(TALLOC_CTX *mem_ctx,
								       struct ldb_message *msg)
{
	struct drsuapi_DsReplicaObjectIdentifier *identifier;
	struct dom_sid *sid;

	identifier = talloc(mem_ctx, struct drsuapi_DsReplicaObjectIdentifier);
	if (identifier == NULL) {
		return NULL;
	}

	identifier->dn = ldb_dn_alloc_linearized(identifier, msg->dn);
	identifier->guid = samdb_result_guid(msg, "objectGUID");

	sid = samdb_result_dom_sid(identifier, msg, "objectSid");
	if (sid) {
		identifier->sid = *sid;
	} else {
		ZERO_STRUCT(identifier->sid);
	}
	return identifier;
}

static int udv_compare(const struct GUID *guid1, struct GUID guid2)
{
	return GUID_compare(guid1, &guid2);
}

/*
  see if we can filter an attribute using the uptodateness_vector
 */
static bool udv_filter(const struct drsuapi_DsReplicaCursorCtrEx *udv,
		       const struct GUID *originating_invocation_id,
		       uint64_t originating_usn)
{
	const struct drsuapi_DsReplicaCursor *c;
	if (udv == NULL) return false;
	BINARY_ARRAY_SEARCH(udv->cursors, udv->count, source_dsa_invocation_id,
			    originating_invocation_id, udv_compare, c);
	if (c && originating_usn <= c->highest_usn) {
		return true;
	}
	return false;

}

static int uint32_t_cmp(uint32_t a1, uint32_t a2)
{
	if (a1 == a2) return 0;
	return a1 > a2 ? 1 : -1;
}

static int uint32_t_ptr_cmp(uint32_t *a1, uint32_t *a2, void *unused)
{
	if (*a1 == *a2) return 0;
	return *a1 > *a2 ? 1 : -1;
}

static WERROR getncchanges_attid_remote_to_local(const struct dsdb_schema *schema,
						 const struct dsdb_syntax_ctx *ctx,
						 enum drsuapi_DsAttributeId remote_attid_as_enum,
						 enum drsuapi_DsAttributeId *local_attid_as_enum,
						 const struct dsdb_attribute **_sa)
{
	WERROR werr;
	const struct dsdb_attribute *sa = NULL;

	if (ctx->pfm_remote == NULL) {
		DEBUG(7, ("No prefixMap supplied, falling back to local prefixMap.\n"));
		goto fail;
	}

	werr = dsdb_attribute_drsuapi_remote_to_local(ctx,
						      remote_attid_as_enum,
						      local_attid_as_enum,
						      _sa);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(3, ("WARNING: Unable to resolve remote attid, falling back to local prefixMap.\n"));
		goto fail;
	}

	return werr;
fail:

	sa = dsdb_attribute_by_attributeID_id(schema, remote_attid_as_enum);
	if (sa == NULL) {
		return WERR_DS_DRA_SCHEMA_MISMATCH;
	} else {
		if (local_attid_as_enum != NULL) {
			*local_attid_as_enum = sa->attributeID_id;
		}
		if (_sa != NULL) {
			*_sa = sa;
		}
		return WERR_OK;
	}
}

/* 
  drsuapi_DsGetNCChanges for one object
*/
static WERROR get_nc_changes_build_object(struct drsuapi_DsReplicaObjectListItemEx *obj,
					  struct ldb_message *msg,
					  struct ldb_context *sam_ctx,
					  struct ldb_dn *ncRoot_dn,
					  bool   is_schema_nc,
					  struct dsdb_schema *schema,
					  DATA_BLOB *session_key,
					  uint64_t highest_usn,
					  uint32_t replica_flags,
					  struct drsuapi_DsPartialAttributeSet *partial_attribute_set,
					  struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector,
					  enum drsuapi_DsExtendedOperation extended_op,
					  bool force_object_return,
					  uint32_t *local_pas)
{
	const struct ldb_val *md_value;
	uint32_t i, n;
	struct replPropertyMetaDataBlob md;
	uint32_t rid = 0;
	enum ndr_err_code ndr_err;
	uint32_t *attids;
	const char *rdn;
	const struct dsdb_attribute *rdn_sa;
	unsigned int instanceType;
	struct dsdb_syntax_ctx syntax_ctx;

	/* make dsdb sytanx context for conversions */
	dsdb_syntax_ctx_init(&syntax_ctx, sam_ctx, schema);
	syntax_ctx.is_schema_nc = is_schema_nc;

	instanceType = ldb_msg_find_attr_as_uint(msg, "instanceType", 0);
	if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
		obj->is_nc_prefix = true;
		obj->parent_object_guid = NULL;
	} else {
		obj->is_nc_prefix = false;
		obj->parent_object_guid = talloc(obj, struct GUID);
		if (obj->parent_object_guid == NULL) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		*obj->parent_object_guid = samdb_result_guid(msg, "parentGUID");
		if (GUID_all_zero(obj->parent_object_guid)) {
			DEBUG(0,(__location__ ": missing parentGUID for %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
	}
	obj->next_object = NULL;

	md_value = ldb_msg_find_ldb_val(msg, "replPropertyMetaData");
	if (!md_value) {
		/* nothing to send */
		return WERR_OK;
	}

	if (instanceType & INSTANCE_TYPE_UNINSTANT) {
		/* don't send uninstantiated objects */
		return WERR_OK;
	}

	ndr_err = ndr_pull_struct_blob(md_value, obj, &md,
				       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (md.version != 1) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	rdn = ldb_dn_get_rdn_name(msg->dn);
	if (rdn == NULL) {
		DEBUG(0,(__location__ ": No rDN for %s\n", ldb_dn_get_linearized(msg->dn)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	rdn_sa = dsdb_attribute_by_lDAPDisplayName(schema, rdn);
	if (rdn_sa == NULL) {
		DEBUG(0,(__location__ ": Can't find dsds_attribute for rDN %s in %s\n",
			 rdn, ldb_dn_get_linearized(msg->dn)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	obj->meta_data_ctr = talloc(obj, struct drsuapi_DsReplicaMetaDataCtr);
	attids = talloc_array(obj, uint32_t, md.ctr.ctr1.count);

	obj->object.identifier = get_object_identifier(obj, msg);
	if (obj->object.identifier == NULL) {
		return WERR_NOMEM;
	}
	dom_sid_split_rid(NULL, &obj->object.identifier->sid, NULL, &rid);

	obj->meta_data_ctr->meta_data = talloc_array(obj, struct drsuapi_DsReplicaMetaData, md.ctr.ctr1.count);
	for (n=i=0; i<md.ctr.ctr1.count; i++) {
		const struct dsdb_attribute *sa;
		bool force_attribute = false;

		/* if the attribute has not changed, and it is not the
		   instanceType then don't include it */
		if (md.ctr.ctr1.array[i].local_usn < highest_usn &&
		    extended_op != DRSUAPI_EXOP_REPL_SECRET &&
		    md.ctr.ctr1.array[i].attid != DRSUAPI_ATTID_instanceType) continue;

		/* don't include the rDN */
		if (md.ctr.ctr1.array[i].attid == rdn_sa->attributeID_id) continue;

		sa = dsdb_attribute_by_attributeID_id(schema, md.ctr.ctr1.array[i].attid);
		if (!sa) {
			DEBUG(0,(__location__ ": Failed to find attribute in schema for attrid %u mentioned in replPropertyMetaData of %s\n",
				 (unsigned int)md.ctr.ctr1.array[i].attid,
				 ldb_dn_get_linearized(msg->dn)));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if (sa->linkID) {
			struct ldb_message_element *el;
			el = ldb_msg_find_element(msg, sa->lDAPDisplayName);
			if (el && el->num_values && dsdb_dn_is_upgraded_link_val(&el->values[0])) {
				/* don't send upgraded links inline */
				continue;
			}
		}

		if (extended_op == DRSUAPI_EXOP_REPL_SECRET &&
		    !dsdb_attr_in_rodc_fas(sa)) {
			force_attribute = true;
			DEBUG(4,("Forcing attribute %s in %s\n",
				 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		}

		/* filter by uptodateness_vector */
		if (md.ctr.ctr1.array[i].attid != DRSUAPI_ATTID_instanceType &&
		    !force_attribute &&
		    udv_filter(uptodateness_vector,
			       &md.ctr.ctr1.array[i].originating_invocation_id,
			       md.ctr.ctr1.array[i].originating_usn)) {
			continue;
		}

		/* filter by partial_attribute_set */
		if (partial_attribute_set) {
			uint32_t *result = NULL;
			BINARY_ARRAY_SEARCH_V(local_pas, partial_attribute_set->num_attids, sa->attributeID_id,
					      uint32_t_cmp, result);
			if (result == NULL) {
				continue;
			}
		}

		obj->meta_data_ctr->meta_data[n].originating_change_time = md.ctr.ctr1.array[i].originating_change_time;
		obj->meta_data_ctr->meta_data[n].version = md.ctr.ctr1.array[i].version;
		obj->meta_data_ctr->meta_data[n].originating_invocation_id = md.ctr.ctr1.array[i].originating_invocation_id;
		obj->meta_data_ctr->meta_data[n].originating_usn = md.ctr.ctr1.array[i].originating_usn;
		attids[n] = md.ctr.ctr1.array[i].attid;
		n++;
	}

	/* ignore it if its an empty change. Note that renames always
	 * change the 'name' attribute, so they won't be ignored by
	 * this

	 * the force_object_return check is used to force an empty
	 * object return when we timeout in the getncchanges loop.
	 * This allows us to return an empty object, which keeps the
	 * client happy while preventing timeouts
	 */
	if (n == 0 ||
	    (n == 1 &&
	     attids[0] == DRSUAPI_ATTID_instanceType &&
	     !force_object_return)) {
		talloc_free(obj->meta_data_ctr);
		obj->meta_data_ctr = NULL;
		return WERR_OK;
	}

	obj->meta_data_ctr->count = n;

	obj->object.flags = DRSUAPI_DS_REPLICA_OBJECT_FROM_MASTER;
	obj->object.attribute_ctr.num_attributes = obj->meta_data_ctr->count;
	obj->object.attribute_ctr.attributes = talloc_array(obj, struct drsuapi_DsReplicaAttribute,
							    obj->object.attribute_ctr.num_attributes);
	if (obj->object.attribute_ctr.attributes == NULL) {
		return WERR_NOMEM;
	}

	/*
	 * Note that the meta_data array and the attributes array must
	 * be the same size and in the same order
	 */
	for (i=0; i<obj->object.attribute_ctr.num_attributes; i++) {
		struct ldb_message_element *el;
		WERROR werr;
		const struct dsdb_attribute *sa;

		sa = dsdb_attribute_by_attributeID_id(schema, attids[i]);
		if (!sa) {
			DEBUG(0,("Unable to find attributeID %u in schema\n", attids[i]));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		el = ldb_msg_find_element(msg, sa->lDAPDisplayName);
		if (el == NULL) {
			/* this happens for attributes that have been removed */
			DEBUG(5,("No element '%s' for attributeID %u in message\n",
				 sa->lDAPDisplayName, attids[i]));
			ZERO_STRUCT(obj->object.attribute_ctr.attributes[i]);
			obj->object.attribute_ctr.attributes[i].attid =
					dsdb_attribute_get_attid(sa, syntax_ctx.is_schema_nc);
		} else {
			werr = sa->syntax->ldb_to_drsuapi(&syntax_ctx, sa, el, obj,
			                                  &obj->object.attribute_ctr.attributes[i]);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,("Unable to convert %s on %s to DRS object - %s\n",
					 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn),
					 win_errstr(werr)));
				return werr;
			}
			/* if DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING is set
			 * check if attribute is secret and send a null value
			 */
			if (replica_flags & DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING) {
				drsuapi_process_secret_attribute(&obj->object.attribute_ctr.attributes[i],
								 &obj->meta_data_ctr->meta_data[i]);
			}
			/* some attributes needs to be encrypted
			   before being sent */
			werr = drsuapi_encrypt_attribute(obj, session_key, rid, 
							 &obj->object.attribute_ctr.attributes[i]);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,("Unable to encrypt %s on %s in DRS object - %s\n",
					 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn),
					 win_errstr(werr)));
				return werr;
			}
		}
		if (attids[i] != obj->object.attribute_ctr.attributes[i].attid) {
			DEBUG(0, ("Unable to replicate attribute %s on %s via DRS, incorrect attributeID:  "
				  "0x%08x vs 0x%08x "
				  "Run dbcheck!\n",
				  sa->lDAPDisplayName,
				  ldb_dn_get_linearized(msg->dn),
				  attids[i],
				  obj->object.attribute_ctr.attributes[i].attid));
			return WERR_DS_DATABASE_ERROR;
		}
	}

	return WERR_OK;
}

/*
  add one linked attribute from an object to the list of linked
  attributes in a getncchanges request
 */
static WERROR get_nc_changes_add_la(TALLOC_CTX *mem_ctx,
				    struct ldb_context *sam_ctx,
				    const struct dsdb_schema *schema,
				    const struct dsdb_attribute *sa,
				    struct ldb_message *msg,
				    struct dsdb_dn *dsdb_dn,
				    struct drsuapi_DsReplicaLinkedAttribute **la_list,
				    uint32_t *la_count,
				    bool is_schema_nc)
{
	struct drsuapi_DsReplicaLinkedAttribute *la;
	bool active;
	NTSTATUS status;
	WERROR werr;

	(*la_list) = talloc_realloc(mem_ctx, *la_list, struct drsuapi_DsReplicaLinkedAttribute, (*la_count)+1);
	W_ERROR_HAVE_NO_MEMORY(*la_list);

	la = &(*la_list)[*la_count];

	la->identifier = get_object_identifier(*la_list, msg);
	W_ERROR_HAVE_NO_MEMORY(la->identifier);

	active = (dsdb_dn_rmd_flags(dsdb_dn->dn) & DSDB_RMD_FLAG_DELETED) == 0;

	if (!active) {
		/* We have to check that the inactive link still point to an existing object */
		struct GUID guid;
		struct ldb_dn *tdn;
		int ret;
		const char *v;

		v = ldb_msg_find_attr_as_string(msg, "isDeleted", "FALSE");
		if (strncmp(v, "TRUE", 4) == 0) {
			/*
			  * Note: we skip the transmition of the deleted link even if the other part used to
			  * know about it because when we transmit the deletion of the object, the link will
			  * be deleted too due to deletion of object where link points and Windows do so.
			  */
			if (dsdb_functional_level(sam_ctx) >= DS_DOMAIN_FUNCTION_2008_R2) {
				v = ldb_msg_find_attr_as_string(msg, "isRecycled", "FALSE");
				/*
				 * On Windows 2008R2 isRecycled is always present even if FL or DL are < FL 2K8R2
				 * if it join an existing domain with deleted objets, it firsts impose to have a
				 * schema with the is-Recycled object and for all deleted objects it adds the isRecycled
				 * either during initial replication or after the getNCChanges.
				 * Behavior of samba has been changed to always have this attribute if it's present in the schema.
				 *
				 * So if FL <2K8R2 isRecycled might be here or not but we don't care, it's meaning less.
				 * If FL >=2K8R2 we are sure that this attribute will be here.
				 * For this kind of forest level we do not return the link if the object is recycled
				 * (isRecycled = true).
				 */
				if (strncmp(v, "TRUE", 4) == 0) {
					DEBUG(2, (" object %s is recycled, not returning linked attribute !\n",
								ldb_dn_get_linearized(msg->dn)));
					return WERR_OK;
				}
			} else {
				return WERR_OK;
			}
		}
		status = dsdb_get_extended_dn_guid(dsdb_dn->dn, &guid, "GUID");
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,(__location__ " Unable to extract GUID in linked attribute '%s' in '%s'\n",
				sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
			return ntstatus_to_werror(status);
		}
		ret = dsdb_find_dn_by_guid(sam_ctx, mem_ctx, &guid, 0, &tdn);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			DEBUG(2, (" Search of guid %s returned 0 objects, skipping it !\n",
						GUID_string(mem_ctx, &guid)));
			return WERR_OK;
		} else if (ret != LDB_SUCCESS) {
			DEBUG(0, (__location__ " Search of guid %s failed with error code %d\n",
						GUID_string(mem_ctx, &guid),
						ret));
			return WERR_OK;
		}
	}
	la->attid = dsdb_attribute_get_attid(sa, is_schema_nc);
	la->flags = active?DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE:0;

	status = dsdb_get_extended_dn_uint32(dsdb_dn->dn, &la->meta_data.version, "RMD_VERSION");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_VERSION in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_nttime(dsdb_dn->dn, &la->meta_data.originating_change_time, "RMD_CHANGETIME");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_CHANGETIME in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_guid(dsdb_dn->dn, &la->meta_data.originating_invocation_id, "RMD_INVOCID");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_INVOCID in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_uint64(dsdb_dn->dn, &la->meta_data.originating_usn, "RMD_ORIGINATING_USN");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_ORIGINATING_USN in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}

	status = dsdb_get_extended_dn_nttime(dsdb_dn->dn, &la->originating_add_time, "RMD_ADDTIME");
	if (!NT_STATUS_IS_OK(status)) {
		/* this is possible for upgraded links */
		la->originating_add_time = la->meta_data.originating_change_time;
	}

	werr = dsdb_dn_la_to_blob(sam_ctx, sa, schema, *la_list, dsdb_dn, &la->value.blob);
	W_ERROR_NOT_OK_RETURN(werr);

	(*la_count)++;
	return WERR_OK;
}


/*
  add linked attributes from an object to the list of linked
  attributes in a getncchanges request
 */
static WERROR get_nc_changes_add_links(struct ldb_context *sam_ctx,
				       TALLOC_CTX *mem_ctx,
				       struct ldb_dn *ncRoot_dn,
				       bool is_schema_nc,
				       struct dsdb_schema *schema,
				       uint64_t highest_usn,
				       uint32_t replica_flags,
				       struct ldb_message *msg,
				       struct drsuapi_DsReplicaLinkedAttribute **la_list,
				       uint32_t *la_count,
				       struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector)
{
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	uint64_t uSNChanged = ldb_msg_find_attr_as_int(msg, "uSNChanged", -1);

	for (i=0; i<msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i];
		const struct dsdb_attribute *sa;
		unsigned int j;

		sa = dsdb_attribute_by_lDAPDisplayName(schema, el->name);

		if (!sa || sa->linkID == 0 || (sa->linkID & 1)) {
			/* we only want forward links */
			continue;
		}

		if (el->num_values && !dsdb_dn_is_upgraded_link_val(&el->values[0])) {
			/* its an old style link, it will have been
			 * sent in the main replication data */
			continue;
		}

		for (j=0; j<el->num_values; j++) {
			struct dsdb_dn *dsdb_dn;
			uint64_t local_usn;
			NTSTATUS status;
			WERROR werr;

			dsdb_dn = dsdb_dn_parse(tmp_ctx, sam_ctx, &el->values[j], sa->syntax->ldap_oid);
			if (dsdb_dn == NULL) {
				DEBUG(1,(__location__ ": Failed to parse DN for %s in %s\n",
					 el->name, ldb_dn_get_linearized(msg->dn)));
				talloc_free(tmp_ctx);
				return WERR_DS_DRA_INTERNAL_ERROR;
			}

			status = dsdb_get_extended_dn_uint64(dsdb_dn->dn, &local_usn, "RMD_LOCAL_USN");
			if (!NT_STATUS_IS_OK(status)) {
				/* this can happen for attributes
				   given to us with old style meta
				   data */
				continue;
			}

			if (local_usn > uSNChanged) {
				DEBUG(1,(__location__ ": uSNChanged less than RMD_LOCAL_USN for %s on %s\n",
					 el->name, ldb_dn_get_linearized(msg->dn)));
				talloc_free(tmp_ctx);
				return WERR_DS_DRA_INTERNAL_ERROR;
			}

			if (local_usn < highest_usn) {
				continue;
			}

			werr = get_nc_changes_add_la(mem_ctx, sam_ctx, schema,
						     sa, msg, dsdb_dn, la_list,
						     la_count, is_schema_nc);
			if (!W_ERROR_IS_OK(werr)) {
				talloc_free(tmp_ctx);
				return werr;
			}
		}
	}

	talloc_free(tmp_ctx);
	return WERR_OK;
}

/*
  fill in the cursors return based on the replUpToDateVector for the ncRoot_dn
 */
static WERROR get_nc_changes_udv(struct ldb_context *sam_ctx,
				 struct ldb_dn *ncRoot_dn,
				 struct drsuapi_DsReplicaCursor2CtrEx *udv)
{
	int ret;

	udv->version = 2;
	udv->reserved1 = 0;
	udv->reserved2 = 0;

	ret = dsdb_load_udv_v2(sam_ctx, ncRoot_dn, udv, &udv->cursors, &udv->count);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to load UDV for %s - %s\n",
			 ldb_dn_get_linearized(ncRoot_dn), ldb_errstring(sam_ctx)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	return WERR_OK;
}


/* comparison function for linked attributes - see CompareLinks() in
 * MS-DRSR section 4.1.10.5.17 */
static int linked_attribute_compare(const struct la_for_sorting *la1,
				    const struct la_for_sorting *la2,
				    void *opaque)
{
	int c;
	c = memcmp(la1->source_guid,
		   la2->source_guid, sizeof(la2->source_guid));
	if (c != 0) {
		return c;
	}

	if (la1->link->attid != la2->link->attid) {
		return la1->link->attid < la2->link->attid? -1:1;
	}

	if ((la1->link->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE) !=
	    (la2->link->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE)) {
		return (la1->link->flags &
			DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE)? 1:-1;
	}

	return memcmp(la1->target_guid,
		      la2->target_guid, sizeof(la2->target_guid));
}

struct drsuapi_changed_objects {
	struct ldb_dn *dn;
	struct GUID guid;
	uint64_t usn;
};

/*
  sort the objects we send by tree order
 */
static int site_res_cmp_anc_order(struct drsuapi_changed_objects *m1,
				  struct drsuapi_changed_objects *m2,
				  struct drsuapi_getncchanges_state *getnc_state)
{
	return ldb_dn_compare(m2->dn, m1->dn);
}

/*
  sort the objects we send first by uSNChanged
 */
static int site_res_cmp_usn_order(struct drsuapi_changed_objects *m1,
				  struct drsuapi_changed_objects *m2,
				  struct drsuapi_getncchanges_state *getnc_state)
{
	int ret;

	ret = ldb_dn_compare(getnc_state->ncRoot_dn, m1->dn);
	if (ret == 0) {
		return -1;
	}

	ret = ldb_dn_compare(getnc_state->ncRoot_dn, m2->dn);
	if (ret == 0) {
		return 1;
	}

	if (m1->usn == m2->usn) {
		return ldb_dn_compare(m2->dn, m1->dn);
	}

	if (m1->usn < m2->usn) {
		return -1;
	}

	return 1;
}


/*
  handle a DRSUAPI_EXOP_FSMO_RID_ALLOC call
 */
static WERROR getncchanges_rid_alloc(struct drsuapi_bind_state *b_state,
				     TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChangesRequest10 *req10,
				     struct drsuapi_DsGetNCChangesCtr6 *ctr6,
				     struct ldb_dn **rid_manager_dn)
{
	struct ldb_dn *req_dn, *ntds_dn = NULL;
	int ret;
	struct ldb_context *ldb = b_state->sam_ctx;
	struct ldb_result *ext_res;
	struct dsdb_fsmo_extended_op *exop;
	bool is_us;

	/*
	  steps:
	    - verify that the DN being asked for is the RID Manager DN
	    - verify that we are the RID Manager
	 */

	/* work out who is the RID Manager, also return to caller */
	ret = samdb_rid_manager_dn(ldb, mem_ctx, rid_manager_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, (__location__ ": Failed to find RID Manager object - %s\n", ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	req_dn = drs_ObjectIdentifier_to_dn(mem_ctx, ldb, req10->naming_context);
	if (!ldb_dn_validate(req_dn) ||
	    ldb_dn_compare(req_dn, *rid_manager_dn) != 0) {
		/* that isn't the RID Manager DN */
		DEBUG(0,(__location__ ": RID Alloc request for wrong DN %s\n",
			 drs_ObjectIdentifier_to_string(mem_ctx, req10->naming_context)));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_MISMATCH;
		return WERR_OK;
	}

	/* TODO: make sure ntds_dn is a valid nTDSDSA object */
	ret = dsdb_find_dn_by_guid(ldb, mem_ctx, &req10->destination_dsa_guid, 0, &ntds_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, (__location__ ": Unable to find NTDS object for guid %s - %s\n",
			  GUID_string(mem_ctx, &req10->destination_dsa_guid), ldb_errstring(ldb)));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_UNKNOWN_CALLER;
		return WERR_OK;
	}

	/* find the DN of the RID Manager */
	ret = samdb_reference_dn_is_our_ntdsa(ldb, *rid_manager_dn, "fSMORoleOwner", &is_us);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to find fSMORoleOwner in RID Manager object\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (!is_us) {
		/* we're not the RID Manager - go away */
		DEBUG(0,(__location__ ": RID Alloc request when not RID Manager\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_OK;
	}

	exop = talloc(mem_ctx, struct dsdb_fsmo_extended_op);
	W_ERROR_HAVE_NO_MEMORY(exop);

	exop->fsmo_info = req10->fsmo_info;
	exop->destination_dsa_guid = req10->destination_dsa_guid;

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed transaction start - %s\n",
			 ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ret = ldb_extended(ldb, DSDB_EXTENDED_ALLOCATE_RID_POOL, exop, &ext_res);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed extended allocation RID pool operation - %s\n",
			 ldb_errstring(ldb)));
		ldb_transaction_cancel(ldb);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed transaction commit - %s\n",
			 ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	talloc_free(ext_res);

	DEBUG(2,("Allocated RID pool for server %s\n",
		 GUID_string(mem_ctx, &req10->destination_dsa_guid)));

	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;

	return WERR_OK;
}

/*
  return an array of SIDs from a ldb_message given an attribute name
  assumes the SIDs are in extended DN format
 */
static WERROR samdb_result_sid_array_dn(struct ldb_context *sam_ctx,
					struct ldb_message *msg,
					TALLOC_CTX *mem_ctx,
					const char *attr,
					const struct dom_sid ***sids)
{
	struct ldb_message_element *el;
	unsigned int i;

	el = ldb_msg_find_element(msg, attr);
	if (!el) {
		*sids = NULL;
		return WERR_OK;
	}

	(*sids) = talloc_array(mem_ctx, const struct dom_sid *, el->num_values + 1);
	W_ERROR_HAVE_NO_MEMORY(*sids);

	for (i=0; i<el->num_values; i++) {
		struct ldb_dn *dn = ldb_dn_from_ldb_val(mem_ctx, sam_ctx, &el->values[i]);
		NTSTATUS status;
		struct dom_sid *sid;

		sid = talloc(*sids, struct dom_sid);
		W_ERROR_HAVE_NO_MEMORY(sid);
		status = dsdb_get_extended_dn_sid(dn, sid, "SID");
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_INTERNAL_DB_CORRUPTION;
		}
		(*sids)[i] = sid;
	}
	(*sids)[i] = NULL;

	return WERR_OK;
}


/*
  return an array of SIDs from a ldb_message given an attribute name
  assumes the SIDs are in NDR form
 */
static WERROR samdb_result_sid_array_ndr(struct ldb_context *sam_ctx,
					 struct ldb_message *msg,
					 TALLOC_CTX *mem_ctx,
					 const char *attr,
					 const struct dom_sid ***sids)
{
	struct ldb_message_element *el;
	unsigned int i;

	el = ldb_msg_find_element(msg, attr);
	if (!el) {
		*sids = NULL;
		return WERR_OK;
	}

	(*sids) = talloc_array(mem_ctx, const struct dom_sid *, el->num_values + 1);
	W_ERROR_HAVE_NO_MEMORY(*sids);

	for (i=0; i<el->num_values; i++) {
		enum ndr_err_code ndr_err;
		struct dom_sid *sid;

		sid = talloc(*sids, struct dom_sid);
		W_ERROR_HAVE_NO_MEMORY(sid);

		ndr_err = ndr_pull_struct_blob(&el->values[i], sid, sid,
					       (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_INTERNAL_DB_CORRUPTION;
		}
		(*sids)[i] = sid;
	}
	(*sids)[i] = NULL;

	return WERR_OK;
}

/*
  see if any SIDs in list1 are in list2
 */
static bool sid_list_match(const struct dom_sid **list1, const struct dom_sid **list2)
{
	unsigned int i, j;
	/* do we ever have enough SIDs here to worry about O(n^2) ? */
	for (i=0; list1[i]; i++) {
		for (j=0; list2[j]; j++) {
			if (dom_sid_equal(list1[i], list2[j])) {
				return true;
			}
		}
	}
	return false;
}

/*
  handle a DRSUAPI_EXOP_REPL_SECRET call
 */
static WERROR getncchanges_repl_secret(struct drsuapi_bind_state *b_state,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsGetNCChangesRequest10 *req10,
				       struct dom_sid *user_sid,
				       struct drsuapi_DsGetNCChangesCtr6 *ctr6,
				       bool has_get_all_changes)
{
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot = req10->naming_context;
	struct ldb_dn *obj_dn = NULL;
	struct ldb_dn *rodc_dn, *krbtgt_link_dn;
	int ret;
	const char *rodc_attrs[] = { "msDS-KrbTgtLink", "msDS-NeverRevealGroup", "msDS-RevealOnDemandGroup", NULL };
	const char *obj_attrs[] = { "tokenGroups", "objectSid", "UserAccountControl", "msDS-KrbTgtLinkBL", NULL };
	struct ldb_result *rodc_res, *obj_res;
	const struct dom_sid **never_reveal_sids, **reveal_sids, **token_sids;
	WERROR werr;

	DEBUG(3,(__location__ ": DRSUAPI_EXOP_REPL_SECRET extended op on %s\n",
		 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot)));

	/*
	 * we need to work out if we will allow this DC to
	 * replicate the secrets for this object
	 *
	 * see 4.1.10.5.14 GetRevealSecretsPolicyForUser for details
	 * of this function
	 */

	if (b_state->sam_ctx_system == NULL) {
		/* this operation needs system level access */
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_ACCESS_DENIED;
		return WERR_DS_DRA_SOURCE_DISABLED;
	}

	/*
	 * In MS-DRSR.pdf 5.99 IsGetNCChangesPermissionGranted
	 *
	 * The pseudo code indicate
	 * revealsecrets = true
	 * if IsRevealSecretRequest(msgIn) then
	 *   if AccessCheckCAR(ncRoot, Ds-Replication-Get-Changes-All) = false
	 *   then
	 *     if (msgIn.ulExtendedOp = EXOP_REPL_SECRETS) then
	 *     <... check if this account is ok to be replicated on this DC ...>
	 *     <... and if not reveal secrets = no ...>
	 *     else
	 *       reveal secrets = false
	 *     endif
	 *   endif
	 * endif
	 *
	 * Which basically means that if you have GET_ALL_CHANGES rights (~== RWDC)
	 * then you can do EXOP_REPL_SECRETS
	 */
	if (has_get_all_changes) {
		goto allowed;
	}

	obj_dn = drs_ObjectIdentifier_to_dn(mem_ctx, b_state->sam_ctx_system, ncRoot);
	if (!ldb_dn_validate(obj_dn)) goto failed;

	rodc_dn = ldb_dn_new_fmt(mem_ctx, b_state->sam_ctx_system, "<SID=%s>",
				 dom_sid_string(mem_ctx, user_sid));
	if (!ldb_dn_validate(rodc_dn)) goto failed;

	/* do the two searches we need */
	ret = dsdb_search_dn(b_state->sam_ctx_system, mem_ctx, &rodc_res, rodc_dn, rodc_attrs,
			     DSDB_SEARCH_SHOW_EXTENDED_DN);
	if (ret != LDB_SUCCESS || rodc_res->count != 1) goto failed;

	ret = dsdb_search_dn(b_state->sam_ctx_system, mem_ctx, &obj_res, obj_dn, obj_attrs, 0);
	if (ret != LDB_SUCCESS || obj_res->count != 1) goto failed;

	/* if the object SID is equal to the user_sid, allow */
	if (dom_sid_equal(user_sid,
			  samdb_result_dom_sid(mem_ctx, obj_res->msgs[0], "objectSid"))) {
		goto allowed;
	}

	/* an RODC is allowed to get its own krbtgt account secrets */
	krbtgt_link_dn = samdb_result_dn(b_state->sam_ctx_system, mem_ctx,
					 rodc_res->msgs[0], "msDS-KrbTgtLink", NULL);
	if (krbtgt_link_dn != NULL &&
	    ldb_dn_compare(obj_dn, krbtgt_link_dn) == 0) {
		goto allowed;
	}

	/* but it isn't allowed to get anyone elses krbtgt secrets */
	if (samdb_result_dn(b_state->sam_ctx_system, mem_ctx,
			    obj_res->msgs[0], "msDS-KrbTgtLinkBL", NULL)) {
		goto denied;
	}

	if (ldb_msg_find_attr_as_uint(obj_res->msgs[0],
				      "userAccountControl", 0) &
	    UF_INTERDOMAIN_TRUST_ACCOUNT) {
		goto denied;
	}

	werr = samdb_result_sid_array_dn(b_state->sam_ctx_system, rodc_res->msgs[0],
					 mem_ctx, "msDS-NeverRevealGroup", &never_reveal_sids);
	if (!W_ERROR_IS_OK(werr)) {
		goto denied;
	}

	werr = samdb_result_sid_array_dn(b_state->sam_ctx_system, rodc_res->msgs[0],
					 mem_ctx, "msDS-RevealOnDemandGroup", &reveal_sids);
	if (!W_ERROR_IS_OK(werr)) {
		goto denied;
	}

	werr = samdb_result_sid_array_ndr(b_state->sam_ctx_system, obj_res->msgs[0],
					 mem_ctx, "tokenGroups", &token_sids);
	if (!W_ERROR_IS_OK(werr) || token_sids==NULL) {
		goto denied;
	}

	if (never_reveal_sids &&
	    sid_list_match(token_sids, never_reveal_sids)) {
		goto denied;
	}

	if (reveal_sids &&
	    sid_list_match(token_sids, reveal_sids)) {
		goto allowed;
	}

	/* default deny */
denied:
	DEBUG(2,(__location__ ": Denied single object with secret replication for %s by RODC %s\n",
		 ldb_dn_get_linearized(obj_dn), ldb_dn_get_linearized(rodc_res->msgs[0]->dn)));
	ctr6->extended_ret = DRSUAPI_EXOP_ERR_NONE;
	return WERR_DS_DRA_ACCESS_DENIED;

allowed:
	DEBUG(2,(__location__ ": Allowed single object with secret replication for %s by %s %s\n",
		 ldb_dn_get_linearized(obj_dn), has_get_all_changes?"RWDC":"RODC",
		 ldb_dn_get_linearized(rodc_res->msgs[0]->dn)));
	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;
	req10->highwatermark.highest_usn = 0;
	return WERR_OK;

failed:
	DEBUG(2,(__location__ ": Failed single secret replication for %s by RODC %s\n",
		 ldb_dn_get_linearized(obj_dn), dom_sid_string(mem_ctx, user_sid)));
	ctr6->extended_ret = DRSUAPI_EXOP_ERR_NONE;
	return WERR_DS_DRA_BAD_DN;
}


/*
  handle a DRSUAPI_EXOP_REPL_OBJ call
 */
static WERROR getncchanges_repl_obj(struct drsuapi_bind_state *b_state,
				    TALLOC_CTX *mem_ctx,
				    struct drsuapi_DsGetNCChangesRequest10 *req10,
				    struct dom_sid *user_sid,
				    struct drsuapi_DsGetNCChangesCtr6 *ctr6)
{
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot = req10->naming_context;

	DEBUG(3,(__location__ ": DRSUAPI_EXOP_REPL_OBJ extended op on %s\n",
		 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot)));

	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;
	return WERR_OK;
}


/*
  handle DRSUAPI_EXOP_FSMO_REQ_ROLE,
  DRSUAPI_EXOP_FSMO_RID_REQ_ROLE,
  and DRSUAPI_EXOP_FSMO_REQ_PDC calls
 */
static WERROR getncchanges_change_master(struct drsuapi_bind_state *b_state,
					 TALLOC_CTX *mem_ctx,
					 struct drsuapi_DsGetNCChangesRequest10 *req10,
					 struct drsuapi_DsGetNCChangesCtr6 *ctr6)
{
	struct ldb_dn *req_dn, *ntds_dn;
	int ret;
	unsigned int i;
	struct ldb_context *ldb = b_state->sam_ctx;
	struct ldb_message *msg;
	bool is_us;

	/*
	  steps:
	    - verify that the client dn exists
	    - verify that we are the current master
	 */

	req_dn = drs_ObjectIdentifier_to_dn(mem_ctx, ldb, req10->naming_context);
	if (!ldb_dn_validate(req_dn)) {
		/* that is not a valid dn */
		DEBUG(0,(__location__ ": FSMO role transfer request for invalid DN %s\n",
			 drs_ObjectIdentifier_to_string(mem_ctx, req10->naming_context)));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_MISMATCH;
		return WERR_OK;
	}

	/* find the DN of the current role owner */
	ret = samdb_reference_dn_is_our_ntdsa(ldb, req_dn, "fSMORoleOwner", &is_us);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to find fSMORoleOwner in RID Manager object\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (!is_us) {
		/* we're not the RID Manager or role owner - go away */
		DEBUG(0,(__location__ ": FSMO role or RID manager transfer owner request when not role owner\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_OK;
	}

	/* change the current master */
	msg = ldb_msg_new(ldb);
	W_ERROR_HAVE_NO_MEMORY(msg);
	msg->dn = drs_ObjectIdentifier_to_dn(msg, ldb, req10->naming_context);
	W_ERROR_HAVE_NO_MEMORY(msg->dn);

	/* TODO: make sure ntds_dn is a valid nTDSDSA object */
	ret = dsdb_find_dn_by_guid(ldb, msg, &req10->destination_dsa_guid, 0, &ntds_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, (__location__ ": Unable to find NTDS object for guid %s - %s\n",
			  GUID_string(mem_ctx, &req10->destination_dsa_guid), ldb_errstring(ldb)));
		talloc_free(msg);
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_UNKNOWN_CALLER;
		return WERR_OK;
	}

	ret = ldb_msg_add_string(msg, "fSMORoleOwner", ldb_dn_get_linearized(ntds_dn));
	if (ret != 0) {
		talloc_free(msg);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed transaction start - %s\n",
			 ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ret = ldb_modify(ldb, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to change current owner - %s\n",
			 ldb_errstring(ldb)));
		ldb_transaction_cancel(ldb);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed transaction commit - %s\n",
			 ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;

	return WERR_OK;
}

/*
  see if this getncchanges request includes a request to reveal secret information
 */
static WERROR dcesrv_drsuapi_is_reveal_secrets_request(struct drsuapi_bind_state *b_state,
						       struct drsuapi_DsGetNCChangesRequest10 *req10,
						       struct dsdb_schema_prefixmap *pfm_remote,
						       bool *is_secret_request)
{
	enum drsuapi_DsExtendedOperation exop;
	uint32_t i;
	struct dsdb_schema *schema;
	struct dsdb_syntax_ctx syntax_ctx;

	*is_secret_request = true;

	exop = req10->extended_op;

	switch (exop) {
	case DRSUAPI_EXOP_FSMO_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_RID_ALLOC:
	case DRSUAPI_EXOP_FSMO_RID_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_REQ_PDC:
	case DRSUAPI_EXOP_FSMO_ABANDON_ROLE:
		/* FSMO exops can reveal secrets */
		*is_secret_request = true;
		return WERR_OK;
	case DRSUAPI_EXOP_REPL_SECRET:
	case DRSUAPI_EXOP_REPL_OBJ:
	case DRSUAPI_EXOP_NONE:
		break;
	}

	if (req10->replica_flags & DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING) {
		*is_secret_request = false;
		return WERR_OK;
	}

	if (exop == DRSUAPI_EXOP_REPL_SECRET ||
	    req10->partial_attribute_set == NULL) {
		/* they want secrets */
		*is_secret_request = true;
		return WERR_OK;
	}

	schema = dsdb_get_schema(b_state->sam_ctx, NULL);
	dsdb_syntax_ctx_init(&syntax_ctx, b_state->sam_ctx, schema);
	syntax_ctx.pfm_remote = pfm_remote;

	/* check the attributes they asked for */
	for (i=0; i<req10->partial_attribute_set->num_attids; i++) {
		const struct dsdb_attribute *sa;
		WERROR werr = getncchanges_attid_remote_to_local(schema,
								 &syntax_ctx,
								 req10->partial_attribute_set->attids[i],
								 NULL,
								 &sa);

		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
				 req10->partial_attribute_set->attids[i], win_errstr(werr)));
			return werr;
		}

		if (!dsdb_attr_in_rodc_fas(sa)) {
			*is_secret_request = true;
			return WERR_OK;
		}
	}

	if (req10->partial_attribute_set_ex) {
		/* check the extended attributes they asked for */
		for (i=0; i<req10->partial_attribute_set_ex->num_attids; i++) {
			const struct dsdb_attribute *sa;
			WERROR werr = getncchanges_attid_remote_to_local(schema,
									 &syntax_ctx,
									 req10->partial_attribute_set_ex->attids[i],
									 NULL,
									 &sa);

			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
					 req10->partial_attribute_set_ex->attids[i], win_errstr(werr)));
				return werr;
			}

			if (!dsdb_attr_in_rodc_fas(sa)) {
				*is_secret_request = true;
				return WERR_OK;
			}
		}
	}

	*is_secret_request = false;
	return WERR_OK;
}

/*
  see if this getncchanges request is only for attributes in the GC
  partial attribute set
 */
static WERROR dcesrv_drsuapi_is_gc_pas_request(struct drsuapi_bind_state *b_state,
					       struct drsuapi_DsGetNCChangesRequest10 *req10,
					       struct dsdb_schema_prefixmap *pfm_remote,
					       bool *is_gc_pas_request)
{
	enum drsuapi_DsExtendedOperation exop;
	uint32_t i;
	struct dsdb_schema *schema;
	struct dsdb_syntax_ctx syntax_ctx;

	exop = req10->extended_op;

	switch (exop) {
	case DRSUAPI_EXOP_FSMO_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_RID_ALLOC:
	case DRSUAPI_EXOP_FSMO_RID_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_REQ_PDC:
	case DRSUAPI_EXOP_FSMO_ABANDON_ROLE:
	case DRSUAPI_EXOP_REPL_SECRET:
		*is_gc_pas_request = false;
		return WERR_OK;
	case DRSUAPI_EXOP_REPL_OBJ:
	case DRSUAPI_EXOP_NONE:
		break;
	}

	if (req10->partial_attribute_set == NULL) {
		/* they want it all */
		*is_gc_pas_request = false;
		return WERR_OK;
	}

	schema = dsdb_get_schema(b_state->sam_ctx, NULL);
	dsdb_syntax_ctx_init(&syntax_ctx, b_state->sam_ctx, schema);
	syntax_ctx.pfm_remote = pfm_remote;

	/* check the attributes they asked for */
	for (i=0; i<req10->partial_attribute_set->num_attids; i++) {
		const struct dsdb_attribute *sa;
		WERROR werr = getncchanges_attid_remote_to_local(schema,
								 &syntax_ctx,
								 req10->partial_attribute_set->attids[i],
								 NULL,
								 &sa);

		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
				 req10->partial_attribute_set->attids[i], win_errstr(werr)));
			return werr;
		}

		if (!sa->isMemberOfPartialAttributeSet) {
			*is_gc_pas_request = false;
			return WERR_OK;
		}
	}

	if (req10->partial_attribute_set_ex) {
		/* check the extended attributes they asked for */
		for (i=0; i<req10->partial_attribute_set_ex->num_attids; i++) {
			const struct dsdb_attribute *sa;
			WERROR werr = getncchanges_attid_remote_to_local(schema,
									 &syntax_ctx,
									 req10->partial_attribute_set_ex->attids[i],
									 NULL,
									 &sa);

			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
					 req10->partial_attribute_set_ex->attids[i], win_errstr(werr)));
				return werr;
			}

			if (!sa->isMemberOfPartialAttributeSet) {
				*is_gc_pas_request = false;
				return WERR_OK;
			}
		}
	}

	*is_gc_pas_request = true;
	return WERR_OK;
}


/*
  map from req8 to req10
 */
static struct drsuapi_DsGetNCChangesRequest10 *
getncchanges_map_req8(TALLOC_CTX *mem_ctx,
		      struct drsuapi_DsGetNCChangesRequest8 *req8)
{
	struct drsuapi_DsGetNCChangesRequest10 *req10 = talloc_zero(mem_ctx,
								    struct drsuapi_DsGetNCChangesRequest10);
	if (req10 == NULL) {
		return NULL;
	}

	req10->destination_dsa_guid = req8->destination_dsa_guid;
	req10->source_dsa_invocation_id = req8->source_dsa_invocation_id;
	req10->naming_context = req8->naming_context;
	req10->highwatermark = req8->highwatermark;
	req10->uptodateness_vector = req8->uptodateness_vector;
	req10->replica_flags = req8->replica_flags;
	req10->max_object_count = req8->max_object_count;
	req10->max_ndr_size = req8->max_ndr_size;
	req10->extended_op = req8->extended_op;
	req10->fsmo_info = req8->fsmo_info;
	req10->partial_attribute_set = req8->partial_attribute_set;
	req10->partial_attribute_set_ex = req8->partial_attribute_set_ex;
	req10->mapping_ctr = req8->mapping_ctr;

	return req10;
}

static const char *collect_objects_attrs[] = { "uSNChanged",
					       "objectGUID" ,
					       NULL };

/**
 * Collects object for normal replication cycle.
 */
static WERROR getncchanges_collect_objects(struct drsuapi_bind_state *b_state,
					   TALLOC_CTX *mem_ctx,
					   struct drsuapi_DsGetNCChangesRequest10 *req10,
					   struct ldb_dn *search_dn,
					   const char *extra_filter,
					   struct ldb_result **search_res)
{
	int ret;
	char* search_filter;
	enum ldb_scope scope = LDB_SCOPE_SUBTREE;
	//const char *extra_filter;
	struct drsuapi_getncchanges_state *getnc_state = b_state->getncchanges_state;

	if (req10->extended_op == DRSUAPI_EXOP_REPL_OBJ ||
	    req10->extended_op == DRSUAPI_EXOP_REPL_SECRET) {
		scope = LDB_SCOPE_BASE;
	}

	//extra_filter = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "object filter");

	//getnc_state->min_usn = req10->highwatermark.highest_usn;

	/* Construct response. */
	search_filter = talloc_asprintf(mem_ctx,
					"(uSNChanged>=%llu)",
					(unsigned long long)(getnc_state->min_usn+1));

	if (extra_filter) {
		search_filter = talloc_asprintf(mem_ctx, "(&%s(%s))", search_filter, extra_filter);
	}

	if (req10->replica_flags & DRSUAPI_DRS_CRITICAL_ONLY) {
		search_filter = talloc_asprintf(mem_ctx,
						"(&%s(isCriticalSystemObject=TRUE))",
						search_filter);
	}

	if (req10->replica_flags & DRSUAPI_DRS_ASYNC_REP) {
		scope = LDB_SCOPE_BASE;
	}

	if (!search_dn) {
		search_dn = getnc_state->ncRoot_dn;
	}

	DEBUG(2,(__location__ ": getncchanges on %s using filter %s\n",
		 ldb_dn_get_linearized(getnc_state->ncRoot_dn), search_filter));
	ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, getnc_state, search_res,
					      search_dn, scope,
					      collect_objects_attrs,
					      search_filter);
	if (ret != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	return WERR_OK;
}

/**
 * Collects object for normal replication cycle.
 */
static WERROR getncchanges_collect_objects_exop(struct drsuapi_bind_state *b_state,
						TALLOC_CTX *mem_ctx,
						struct drsuapi_DsGetNCChangesRequest10 *req10,
						struct drsuapi_DsGetNCChangesCtr6 *ctr6,
						struct ldb_dn *search_dn,
						const char *extra_filter,
						struct ldb_result **search_res)
{
	/* we have nothing to do in case of ex-op failure */
	if (ctr6->extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
		return WERR_OK;
	}

	switch (req10->extended_op) {
	case DRSUAPI_EXOP_FSMO_RID_ALLOC:
	{
		int ret;
		struct ldb_dn *ntds_dn = NULL;
		struct ldb_dn *server_dn = NULL;
		struct ldb_dn *machine_dn = NULL;
		struct ldb_dn *rid_set_dn = NULL;
		struct ldb_result *search_res2 = NULL;
		struct ldb_result *search_res3 = NULL;
		TALLOC_CTX *frame = talloc_stackframe();
		/* get RID manager, RID set and server DN (in that order) */

		/* This first search will get the RID Manager */
		ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, frame,
						      search_res,
						      search_dn, LDB_SCOPE_BASE,
						      collect_objects_attrs,
						      NULL);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Manager object %s - %s",
				  ldb_dn_get_linearized(search_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if ((*search_res)->count != 1) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Manager object %s - %u objects returned",
				  ldb_dn_get_linearized(search_dn),
				  (*search_res)->count));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* Now extend it to the RID set */

		/* Find the computer account DN for the destination
		 * dsa GUID specified */

		ret = dsdb_find_dn_by_guid(b_state->sam_ctx, frame,
					   &req10->destination_dsa_guid, 0,
					   &ntds_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Unable to find NTDS object for guid %s - %s\n",
				  GUID_string(frame,
					      &req10->destination_dsa_guid),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		server_dn = ldb_dn_get_parent(frame, ntds_dn);
		if (!server_dn) {
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		ret = samdb_reference_dn(b_state->sam_ctx, frame, server_dn,
					 "serverReference", &machine_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to find serverReference in %s - %s",
				  ldb_dn_get_linearized(server_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		ret = samdb_reference_dn(b_state->sam_ctx, frame, machine_dn,
					 "rIDSetReferences", &rid_set_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to find rIDSetReferences in %s - %s",
				  ldb_dn_get_linearized(server_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}


		/* This first search will get the RID Manager, now get the RID set */
		ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, frame,
						      &search_res2,
						      rid_set_dn, LDB_SCOPE_BASE,
						      collect_objects_attrs,
						      NULL);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Set object %s - %s",
				  ldb_dn_get_linearized(rid_set_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if (search_res2->count != 1) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Set object %s - %u objects returned",
				  ldb_dn_get_linearized(rid_set_dn),
				  search_res2->count));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* Finally get the server DN */
		ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, frame,
						      &search_res3,
						      machine_dn, LDB_SCOPE_BASE,
						      collect_objects_attrs,
						      NULL);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get server object %s - %s",
				  ldb_dn_get_linearized(server_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if (search_res3->count != 1) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get server object %s - %u objects returned",
				  ldb_dn_get_linearized(server_dn),
				  search_res3->count));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* Now extend the original search_res with these answers */
		(*search_res)->count = 3;

		(*search_res)->msgs = talloc_realloc(frame, (*search_res)->msgs,
						     struct ldb_message *,
						     (*search_res)->count);
		if ((*search_res)->msgs == NULL) {
			TALLOC_FREE(frame);
			return WERR_NOMEM;
		}


		talloc_steal(mem_ctx, *search_res);
		(*search_res)->msgs[1] =
			talloc_steal((*search_res)->msgs, search_res2->msgs[0]);
		(*search_res)->msgs[2] =
			talloc_steal((*search_res)->msgs, search_res3->msgs[0]);

		TALLOC_FREE(frame);
		return WERR_OK;
	}
	default:
		/* TODO: implement extended op specific collection
		 * of objects. Right now we just normal procedure
		 * for collecting objects */
		return getncchanges_collect_objects(b_state, mem_ctx, req10, search_dn, extra_filter, search_res);
	}
}

/* 
  drsuapi_DsGetNCChanges

  see MS-DRSR 4.1.10.5.2 for basic logic of this function
*/
WERROR dcesrv_drsuapi_DsGetNCChanges(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChanges *r)
{
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot;
	int ret;
	uint32_t i, k;
	struct dsdb_schema *schema;
	struct drsuapi_DsReplicaOIDMapping_Ctr *ctr;
	struct drsuapi_DsReplicaObjectListItemEx **currentObject;
	NTSTATUS status;
	DATA_BLOB session_key;
	WERROR werr;
	struct dcesrv_handle *h;
	struct drsuapi_bind_state *b_state;
	struct drsuapi_getncchanges_state *getnc_state;
	struct drsuapi_DsGetNCChangesRequest10 *req10;
	uint32_t options;
	uint32_t max_objects;
	uint32_t max_links;
	uint32_t link_count = 0;
	uint32_t link_total = 0;
	uint32_t link_given = 0;
	struct ldb_dn *search_dn = NULL;
	bool am_rodc, null_scope=false;
	enum security_user_level security_level;
	struct ldb_context *sam_ctx;
	struct dom_sid *user_sid;
	bool is_secret_request;
	bool is_gc_pas_request;
	struct drsuapi_changed_objects *changes;
	time_t max_wait;
	time_t start = time(NULL);
	bool max_wait_reached = false;
	bool has_get_all_changes = false;
	struct GUID invocation_id;
	static const struct drsuapi_DsReplicaLinkedAttribute no_linked_attr;
	struct dsdb_schema_prefixmap *pfm_remote = NULL;
	bool full = true;
	uint32_t *local_pas = NULL;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	sam_ctx = b_state->sam_ctx_system?b_state->sam_ctx_system:b_state->sam_ctx;

	invocation_id = *(samdb_ntds_invocation_id(sam_ctx));

	*r->out.level_out = 6;
	/* TODO: linked attributes*/
	r->out.ctr->ctr6.linked_attributes_count = 0;
	r->out.ctr->ctr6.linked_attributes = discard_const_p(struct drsuapi_DsReplicaLinkedAttribute, &no_linked_attr);

	r->out.ctr->ctr6.object_count = 0;
	r->out.ctr->ctr6.nc_object_count = 0;
	r->out.ctr->ctr6.more_data = false;
	r->out.ctr->ctr6.uptodateness_vector = NULL;
	r->out.ctr->ctr6.source_dsa_guid = *(samdb_ntds_objectGUID(sam_ctx));
	r->out.ctr->ctr6.source_dsa_invocation_id = *(samdb_ntds_invocation_id(sam_ctx));
	r->out.ctr->ctr6.first_object = NULL;

	/* a RODC doesn't allow for any replication */
	ret = samdb_rodc(sam_ctx, &am_rodc);
	if (ret == LDB_SUCCESS && am_rodc) {
		DEBUG(0,(__location__ ": DsGetNCChanges attempt on RODC\n"));
		return WERR_DS_DRA_SOURCE_DISABLED;
	}

	/* Check request revision. 
	 */
	switch (r->in.level) {
	case 8:
		req10 = getncchanges_map_req8(mem_ctx, &r->in.req->req8);
		if (req10 == NULL) {
			return WERR_NOMEM;
		}
		break;
	case 10:
		req10 = &r->in.req->req10;
		break;
	default:
		DEBUG(0,(__location__ ": Request for DsGetNCChanges with unsupported level %u\n",
			 r->in.level));
		return WERR_REVISION_MISMATCH;
	}


        /* Perform access checks. */
	/* TODO: we need to support a sync on a specific non-root
	 * DN. We'll need to find the real partition root here */
	ncRoot = req10->naming_context;
	if (ncRoot == NULL) {
		DEBUG(0,(__location__ ": Request for DsGetNCChanges with no NC\n"));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	if (samdb_ntds_options(sam_ctx, &options) != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if ((options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) &&
	    !(req10->replica_flags & DRSUAPI_DRS_SYNC_FORCED)) {
		return WERR_DS_DRA_SOURCE_DISABLED;
	}

	user_sid = &dce_call->conn->auth_state.session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

	/* all clients must have GUID_DRS_GET_CHANGES */
	werr = drs_security_access_check_nc_root(b_state->sam_ctx,
						 mem_ctx,
						 dce_call->conn->auth_state.session_info->security_token,
						 req10->naming_context,
						 GUID_DRS_GET_CHANGES);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	if (dsdb_functional_level(sam_ctx) >= DS_DOMAIN_FUNCTION_2008) {
		full = req10->partial_attribute_set == NULL &&
		       req10->partial_attribute_set_ex == NULL;
	} else {
		full = (options & DRSUAPI_DRS_WRIT_REP) != 0;
	}

	werr = dsdb_schema_pfm_from_drsuapi_pfm(&req10->mapping_ctr, true,
						mem_ctx, &pfm_remote, NULL);

	/* We were supplied a partial attribute set, without the prefix map! */
	if (!full && !W_ERROR_IS_OK(werr)) {
		if (req10->mapping_ctr.num_mappings == 0) {
			/*
			 * Despite the fact MS-DRSR specifies that this shouldn't
			 * happen, Windows RODCs will in fact not provide a prefixMap.
			 */
			DEBUG(5,(__location__ ": Failed to provide a remote prefixMap,"
				 " falling back to local prefixMap\n"));
		} else {
			DEBUG(0,(__location__ ": Failed to decode remote prefixMap: %s\n",
				 win_errstr(werr)));
			return werr;
		}
	}

	/* allowed if the GC PAS and client has
	   GUID_DRS_GET_FILTERED_ATTRIBUTES */
	werr = dcesrv_drsuapi_is_gc_pas_request(b_state, req10, pfm_remote, &is_gc_pas_request);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}
	if (is_gc_pas_request) {
		werr = drs_security_access_check_nc_root(b_state->sam_ctx,
							 mem_ctx,
							 dce_call->conn->auth_state.session_info->security_token,
							 req10->naming_context,
							 GUID_DRS_GET_FILTERED_ATTRIBUTES);
		if (W_ERROR_IS_OK(werr)) {
			goto allowed;
		}
	}

	werr = dcesrv_drsuapi_is_reveal_secrets_request(b_state, req10,
							pfm_remote,
							&is_secret_request);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}
	if (is_secret_request && req10->extended_op != DRSUAPI_EXOP_REPL_SECRET) {
		werr = drs_security_access_check_nc_root(b_state->sam_ctx,
							 mem_ctx,
							 dce_call->conn->auth_state.session_info->security_token,
							 req10->naming_context,
							 GUID_DRS_GET_ALL_CHANGES);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		} else {
			has_get_all_changes = true;
		}
	}

allowed:
	/* for non-administrator replications, check that they have
	   given the correct source_dsa_invocation_id */
	security_level = security_session_user_level(dce_call->conn->auth_state.session_info,
						     samdb_domain_sid(sam_ctx));
	if (security_level == SECURITY_RO_DOMAIN_CONTROLLER) {
		if (req10->replica_flags & DRSUAPI_DRS_WRIT_REP) {
			/* we rely on this flag being unset for RODC requests */
			req10->replica_flags &= ~DRSUAPI_DRS_WRIT_REP;
		}
	}

	if (req10->replica_flags & DRSUAPI_DRS_FULL_SYNC_PACKET) {
		/* Ignore the _in_ uptpdateness vector*/
		req10->uptodateness_vector = NULL;
	}

	if (GUID_all_zero(&req10->source_dsa_invocation_id)) {
		req10->source_dsa_invocation_id = invocation_id;
	}

	if (!GUID_equal(&req10->source_dsa_invocation_id, &invocation_id)) {
		/*
		 * The given highwatermark is only valid relative to the
		 * specified source_dsa_invocation_id.
		 */
		ZERO_STRUCT(req10->highwatermark);
	}

	getnc_state = b_state->getncchanges_state;

	/* see if a previous replication has been abandoned */
	if (getnc_state) {
		struct ldb_dn *new_dn = drs_ObjectIdentifier_to_dn(getnc_state, sam_ctx, ncRoot);
		if (ldb_dn_compare(new_dn, getnc_state->ncRoot_dn) != 0) {
			DEBUG(0,(__location__ ": DsGetNCChanges 2nd replication on different DN %s %s (last_dn %s)\n",
				 ldb_dn_get_linearized(new_dn),
				 ldb_dn_get_linearized(getnc_state->ncRoot_dn),
				 ldb_dn_get_linearized(getnc_state->last_dn)));
			talloc_free(getnc_state);
			getnc_state = NULL;
		}
	}

	if (getnc_state) {
		ret = drsuapi_DsReplicaHighWaterMark_cmp(&getnc_state->last_hwm,
							 &req10->highwatermark);
		if (ret != 0) {
			DEBUG(0,(__location__ ": DsGetNCChanges 2nd replication "
				 "on DN %s %s highwatermark (last_dn %s)\n",
				 ldb_dn_get_linearized(getnc_state->ncRoot_dn),
				 (ret > 0) ? "older" : "newer",
				 ldb_dn_get_linearized(getnc_state->last_dn)));
			talloc_free(getnc_state);
			getnc_state = NULL;
		}
	}

	if (getnc_state == NULL) {
		getnc_state = talloc_zero(b_state, struct drsuapi_getncchanges_state);
		if (getnc_state == NULL) {
			return WERR_NOMEM;
		}
		b_state->getncchanges_state = getnc_state;
		getnc_state->ncRoot_dn = drs_ObjectIdentifier_to_dn(getnc_state, sam_ctx, ncRoot);

		/* find out if we are to replicate Schema NC */
		ret = ldb_dn_compare_base(ldb_get_schema_basedn(b_state->sam_ctx),
					  getnc_state->ncRoot_dn);

		getnc_state->is_schema_nc = (0 == ret);

		if (req10->extended_op != DRSUAPI_EXOP_NONE) {
			r->out.ctr->ctr6.extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;
		}

		/*
		 * This is the first replication cycle and it is
		 * a good place to handle extended operations
		 *
		 * FIXME: we don't fully support extended operations yet
		 */
		switch (req10->extended_op) {
		case DRSUAPI_EXOP_NONE:
			break;
		case DRSUAPI_EXOP_FSMO_RID_ALLOC:
			werr = getncchanges_rid_alloc(b_state, mem_ctx, req10, &r->out.ctr->ctr6, &search_dn);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_REPL_SECRET:
			werr = getncchanges_repl_secret(b_state, mem_ctx, req10,
						        user_sid,
						        &r->out.ctr->ctr6,
						        has_get_all_changes);
			r->out.result = werr;
			W_ERROR_NOT_OK_RETURN(werr);
			break;
		case DRSUAPI_EXOP_FSMO_REQ_ROLE:
			werr = getncchanges_change_master(b_state, mem_ctx, req10, &r->out.ctr->ctr6);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_FSMO_RID_REQ_ROLE:
			werr = getncchanges_change_master(b_state, mem_ctx, req10, &r->out.ctr->ctr6);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_FSMO_REQ_PDC:
			werr = getncchanges_change_master(b_state, mem_ctx, req10, &r->out.ctr->ctr6);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_REPL_OBJ:
			werr = getncchanges_repl_obj(b_state, mem_ctx, req10, user_sid, &r->out.ctr->ctr6);
			r->out.result = werr;
			W_ERROR_NOT_OK_RETURN(werr);
			break;

		case DRSUAPI_EXOP_FSMO_ABANDON_ROLE:

			DEBUG(0,(__location__ ": Request for DsGetNCChanges unsupported extended op 0x%x\n",
				 (unsigned)req10->extended_op));
			return WERR_DS_DRA_NOT_SUPPORTED;
		}
	}

	if (!ldb_dn_validate(getnc_state->ncRoot_dn) ||
	    ldb_dn_is_null(getnc_state->ncRoot_dn)) {
		DEBUG(0,(__location__ ": Bad DN '%s'\n",
			 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot)));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	/* we need the session key for encrypting password attributes */
	status = dcesrv_inherited_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": Failed to get session key\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	/* 
	   TODO: MS-DRSR section 4.1.10.1.1
	   Work out if this is the start of a new cycle */

	if (getnc_state->guids == NULL) {
		const char *extra_filter;
		struct ldb_result *search_res = NULL;

		extra_filter = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "object filter");

		getnc_state->min_usn = req10->highwatermark.highest_usn;
		getnc_state->max_usn = getnc_state->min_usn;

		getnc_state->final_udv = talloc_zero(getnc_state,
					struct drsuapi_DsReplicaCursor2CtrEx);
		if (getnc_state->final_udv == NULL) {
			return WERR_NOMEM;
		}
		werr = get_nc_changes_udv(sam_ctx, getnc_state->ncRoot_dn,
					  getnc_state->final_udv);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		if (req10->extended_op == DRSUAPI_EXOP_NONE) {
			werr = getncchanges_collect_objects(b_state, mem_ctx, req10,
							    search_dn, extra_filter,
							    &search_res);
		} else {
			werr = getncchanges_collect_objects_exop(b_state, mem_ctx, req10,
								 &r->out.ctr->ctr6,
								 search_dn, extra_filter,
								 &search_res);
		}
		W_ERROR_NOT_OK_RETURN(werr);

		/* extract out the GUIDs list */
		getnc_state->num_records = search_res ? search_res->count : 0;
		getnc_state->guids = talloc_array(getnc_state, struct GUID, getnc_state->num_records);
		W_ERROR_HAVE_NO_MEMORY(getnc_state->guids);

		changes = talloc_array(getnc_state,
				       struct drsuapi_changed_objects,
				       getnc_state->num_records);
		W_ERROR_HAVE_NO_MEMORY(changes);

		for (i=0; i<getnc_state->num_records; i++) {
			changes[i].dn = search_res->msgs[i]->dn;
			changes[i].guid = samdb_result_guid(search_res->msgs[i], "objectGUID");
			changes[i].usn = ldb_msg_find_attr_as_uint64(search_res->msgs[i], "uSNChanged", 0);

			if (changes[i].usn > getnc_state->max_usn) {
				getnc_state->max_usn = changes[i].usn;
			}
		}

		/* RID_ALLOC returns 3 objects in a fixed order */
		if (req10->extended_op == DRSUAPI_EXOP_FSMO_RID_ALLOC) {
			/* Do nothing */
		} else if (req10->replica_flags & DRSUAPI_DRS_GET_ANC) {
			LDB_TYPESAFE_QSORT(changes,
					   getnc_state->num_records,
					   getnc_state,
					   site_res_cmp_anc_order);
		} else {
			LDB_TYPESAFE_QSORT(changes,
					   getnc_state->num_records,
					   getnc_state,
					   site_res_cmp_usn_order);
		}

		for (i=0; i < getnc_state->num_records; i++) {
			getnc_state->guids[i] = changes[i].guid;
			if (GUID_all_zero(&getnc_state->guids[i])) {
				DEBUG(2,("getncchanges: bad objectGUID from %s\n",
					 ldb_dn_get_linearized(search_res->msgs[i]->dn)));
				return WERR_DS_DRA_INTERNAL_ERROR;
			}
		}

		getnc_state->final_hwm.tmp_highest_usn = getnc_state->max_usn;
		getnc_state->final_hwm.reserved_usn = 0;
		getnc_state->final_hwm.highest_usn = getnc_state->max_usn;

		talloc_free(search_res);
		talloc_free(changes);
	}

	if (req10->uptodateness_vector) {
		/* make sure its sorted */
		TYPESAFE_QSORT(req10->uptodateness_vector->cursors,
			       req10->uptodateness_vector->count,
			       drsuapi_DsReplicaCursor_compare);
	}

	/* Prefix mapping */
	schema = dsdb_get_schema(sam_ctx, mem_ctx);
	if (!schema) {
		DEBUG(0,("No schema in sam_ctx\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	r->out.ctr->ctr6.naming_context = talloc(mem_ctx, struct drsuapi_DsReplicaObjectIdentifier);
	*r->out.ctr->ctr6.naming_context = *ncRoot;

	if (dsdb_find_guid_by_dn(sam_ctx, getnc_state->ncRoot_dn,
				 &r->out.ctr->ctr6.naming_context->guid) != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to find GUID of ncRoot_dn %s\n",
			 ldb_dn_get_linearized(getnc_state->ncRoot_dn)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	/* find the SID if there is one */
	dsdb_find_sid_by_dn(sam_ctx, getnc_state->ncRoot_dn, &r->out.ctr->ctr6.naming_context->sid);

	dsdb_get_oid_mappings_drsuapi(schema, true, mem_ctx, &ctr);
	r->out.ctr->ctr6.mapping_ctr = *ctr;

	r->out.ctr->ctr6.source_dsa_guid = *(samdb_ntds_objectGUID(sam_ctx));
	r->out.ctr->ctr6.source_dsa_invocation_id = *(samdb_ntds_invocation_id(sam_ctx));

	r->out.ctr->ctr6.old_highwatermark = req10->highwatermark;
	r->out.ctr->ctr6.new_highwatermark = req10->highwatermark;

	currentObject = &r->out.ctr->ctr6.first_object;

	max_objects = lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "max object sync", 1000);
	/*
	 * The client control here only applies in normal replication, not extended
	 * operations, which return a fixed set, even if the caller
	 * sets max_object_count == 0
	 */
	if (req10->extended_op == DRSUAPI_EXOP_NONE) {
		/* use this to force single objects at a time, which is useful
		 * for working out what object is giving problems
		 */
		if (req10->max_object_count < max_objects) {
			max_objects = req10->max_object_count;
		}
	}
	/*
	 * TODO: work out how the maximum should be calculated
	 */
	max_links = lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "max link sync", 1500);

	/*
	 * Maximum time that we can spend in a getncchanges
	 * in order to avoid timeout of the other part.
	 * 10 seconds by default.
	 */
	max_wait = lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "max work time", 10);

	if (req10->partial_attribute_set != NULL) {
		struct dsdb_syntax_ctx syntax_ctx;
		uint32_t j = 0;

		dsdb_syntax_ctx_init(&syntax_ctx, b_state->sam_ctx, schema);
		syntax_ctx.pfm_remote = pfm_remote;

		local_pas = talloc_array(b_state, uint32_t, req10->partial_attribute_set->num_attids);

		for (j = 0; j < req10->partial_attribute_set->num_attids; j++) {
			getncchanges_attid_remote_to_local(schema,
							   &syntax_ctx,
							   req10->partial_attribute_set->attids[j],
							   (enum drsuapi_DsAttributeId *)&local_pas[j],
							   NULL);
		}

		LDB_TYPESAFE_QSORT(local_pas,
				   req10->partial_attribute_set->num_attids,
				   NULL,
				   uint32_t_ptr_cmp);
	}

	for (i=getnc_state->num_processed;
	     i<getnc_state->num_records &&
		     !null_scope &&
		     (r->out.ctr->ctr6.object_count < max_objects)
		     && !max_wait_reached;
	    i++) {
		int uSN;
		struct drsuapi_DsReplicaObjectListItemEx *obj;
		struct ldb_message *msg;
		static const char * const msg_attrs[] = {
					    "*",
					    "nTSecurityDescriptor",
					    "parentGUID",
					    "replPropertyMetaData",
					    DSDB_SECRET_ATTRIBUTES,
					    NULL };
		struct ldb_result *msg_res;
		struct ldb_dn *msg_dn;

		obj = talloc_zero(mem_ctx, struct drsuapi_DsReplicaObjectListItemEx);
		W_ERROR_HAVE_NO_MEMORY(obj);

		msg_dn = ldb_dn_new_fmt(obj, sam_ctx, "<GUID=%s>", GUID_string(obj, &getnc_state->guids[i]));
		W_ERROR_HAVE_NO_MEMORY(msg_dn);


		/* by re-searching here we avoid having a lot of full
		 * records in memory between calls to getncchanges
		 */
		ret = drsuapi_search_with_extended_dn(sam_ctx, obj, &msg_res,
						      msg_dn,
						      LDB_SCOPE_BASE, msg_attrs, NULL);
		if (ret != LDB_SUCCESS) {
			if (ret != LDB_ERR_NO_SUCH_OBJECT) {
				DEBUG(1,("getncchanges: failed to fetch DN %s - %s\n",
					 ldb_dn_get_extended_linearized(obj, msg_dn, 1), ldb_errstring(sam_ctx)));
			}
			talloc_free(obj);
			continue;
		}

		msg = msg_res->msgs[0];

		max_wait_reached = (time(NULL) - start > max_wait);

		werr = get_nc_changes_build_object(obj, msg,
						   sam_ctx, getnc_state->ncRoot_dn,
						   getnc_state->is_schema_nc,
						   schema, &session_key, getnc_state->min_usn,
						   req10->replica_flags,
						   req10->partial_attribute_set,
						   req10->uptodateness_vector,
						   req10->extended_op,
						   max_wait_reached,
						   local_pas);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		werr = get_nc_changes_add_links(sam_ctx, getnc_state,
						getnc_state->ncRoot_dn,
						getnc_state->is_schema_nc,
						schema, getnc_state->min_usn,
						req10->replica_flags,
						msg,
						&getnc_state->la_list,
						&getnc_state->la_count,
						req10->uptodateness_vector);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		uSN = ldb_msg_find_attr_as_int(msg, "uSNChanged", -1);
		if (uSN > getnc_state->max_usn) {
			/*
			 * Only report the max_usn we had at the start
			 * of the replication cycle.
			 *
			 * If this object has changed lately we better
			 * let the destination dsa refetch the change.
			 * This is better than the risk of loosing some
			 * objects or linked attributes.
			 */
			uSN = 0;
		}
		if (uSN > r->out.ctr->ctr6.new_highwatermark.tmp_highest_usn) {
			r->out.ctr->ctr6.new_highwatermark.tmp_highest_usn = uSN;
			r->out.ctr->ctr6.new_highwatermark.reserved_usn = 0;
		}

		if (obj->meta_data_ctr == NULL) {
			DEBUG(8,(__location__ ": getncchanges skipping send of object %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			/* no attributes to send */
			talloc_free(obj);
			continue;
		}

		r->out.ctr->ctr6.object_count++;

		*currentObject = obj;
		currentObject = &obj->next_object;

		DEBUG(8,(__location__ ": replicating object %s\n", ldb_dn_get_linearized(msg->dn)));

		talloc_free(getnc_state->last_dn);
		getnc_state->last_dn = talloc_move(getnc_state, &msg->dn);

		talloc_free(msg_res);
		talloc_free(msg_dn);
	}

	getnc_state->num_processed = i;

	r->out.ctr->ctr6.nc_object_count = getnc_state->num_records;

	/* the client can us to call UpdateRefs on its behalf to
	   re-establish monitoring of the NC */
	if ((req10->replica_flags & (DRSUAPI_DRS_ADD_REF | DRSUAPI_DRS_REF_GCSPN)) &&
	    !GUID_all_zero(&req10->destination_dsa_guid)) {
		struct drsuapi_DsReplicaUpdateRefsRequest1 ureq;
		DEBUG(3,("UpdateRefs on getncchanges for %s\n",
			 GUID_string(mem_ctx, &req10->destination_dsa_guid)));
		ureq.naming_context = ncRoot;
		ureq.dest_dsa_dns_name = samdb_ntds_msdcs_dns_name(b_state->sam_ctx, mem_ctx,
								   &req10->destination_dsa_guid);
		if (!ureq.dest_dsa_dns_name) {
			return WERR_NOMEM;
		}
		ureq.dest_dsa_guid = req10->destination_dsa_guid;
		ureq.options = DRSUAPI_DRS_ADD_REF |
			DRSUAPI_DRS_ASYNC_OP |
			DRSUAPI_DRS_GETCHG_CHECK;

		/* we also need to pass through the
		   DRSUAPI_DRS_REF_GCSPN bit so that repsTo gets flagged
		   to send notifies using the GC SPN */
		ureq.options |= (req10->replica_flags & DRSUAPI_DRS_REF_GCSPN);

		werr = drsuapi_UpdateRefs(b_state, mem_ctx, &ureq);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Failed UpdateRefs on %s for %s in DsGetNCChanges - %s\n",
				 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot), ureq.dest_dsa_dns_name,
				 win_errstr(werr)));
		}
	}

	/*
	 * TODO:
	 * This is just a guess, how to calculate the
	 * number of linked attributes to send, we need to
	 * find out how to do this right.
	 */
	if (r->out.ctr->ctr6.object_count >= max_links) {
		max_links = 0;
	} else {
		max_links -= r->out.ctr->ctr6.object_count;
	}

	link_total = getnc_state->la_count;

	if (i < getnc_state->num_records) {
		r->out.ctr->ctr6.more_data = true;
	} else {
		/* sort the whole array the first time */
		if (getnc_state->la_sorted == NULL) {
			int j;
			struct la_for_sorting *guid_array = talloc_array(getnc_state, struct la_for_sorting, getnc_state->la_count);
			if (guid_array == NULL) {
				DEBUG(0, ("Out of memory allocating %u linked attributes for sorting", getnc_state->la_count));
				return WERR_NOMEM;
			}
			for (j = 0; j < getnc_state->la_count; j++) {
				/* we need to get the target GUIDs to compare */
				struct dsdb_dn *dn;
				const struct drsuapi_DsReplicaLinkedAttribute *la = &getnc_state->la_list[j];
				const struct dsdb_attribute *schema_attrib;
				const struct ldb_val *target_guid;
				DATA_BLOB source_guid;
				TALLOC_CTX *frame = talloc_stackframe();

				schema_attrib = dsdb_attribute_by_attributeID_id(schema, la->attid);

				werr = dsdb_dn_la_from_blob(sam_ctx, schema_attrib, schema, frame, la->value.blob, &dn);
				if (!W_ERROR_IS_OK(werr)) {
					DEBUG(0,(__location__ ": Bad la blob in sort\n"));
					TALLOC_FREE(frame);
					return werr;
				}

				/* Extract the target GUID in NDR form */
				target_guid = ldb_dn_get_extended_component(dn->dn, "GUID");
				if (target_guid == NULL
				    || target_guid->length != sizeof(guid_array[0].target_guid)) {
					status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
				} else {
					/* Repack the source GUID as NDR for sorting */
					status = GUID_to_ndr_blob(&la->identifier->guid,
								  frame,
								  &source_guid);
				}

				if (!NT_STATUS_IS_OK(status)
				    || source_guid.length != sizeof(guid_array[0].source_guid)) {
					DEBUG(0,(__location__ ": Bad la guid in sort\n"));
					TALLOC_FREE(frame);
					return ntstatus_to_werror(status);
				}

				guid_array[j].link = &getnc_state->la_list[j];
				memcpy(guid_array[j].target_guid, target_guid->data,
				       sizeof(guid_array[j].target_guid));
				memcpy(guid_array[j].source_guid, source_guid.data,
				       sizeof(guid_array[j].source_guid));
				TALLOC_FREE(frame);
			}

			LDB_TYPESAFE_QSORT(guid_array, getnc_state->la_count, NULL, linked_attribute_compare);
			getnc_state->la_sorted = guid_array;
		}

		link_count = getnc_state->la_count - getnc_state->la_idx;
		link_count = MIN(max_links, link_count);

		r->out.ctr->ctr6.linked_attributes_count = link_count;
		r->out.ctr->ctr6.linked_attributes = talloc_array(r->out.ctr, struct drsuapi_DsReplicaLinkedAttribute, link_count);
		if (r->out.ctr->ctr6.linked_attributes == NULL) {
			DEBUG(0, ("Out of memory allocating %u linked attributes for output", link_count));
			return WERR_NOMEM;
		}

		for (k = 0; k < link_count; k++) {
			r->out.ctr->ctr6.linked_attributes[k]
				= *getnc_state->la_sorted[getnc_state->la_idx + k].link;
		}

		getnc_state->la_idx += link_count;
		link_given = getnc_state->la_idx;

		if (getnc_state->la_idx < getnc_state->la_count) {
			r->out.ctr->ctr6.more_data = true;
		}
	}

	if (!r->out.ctr->ctr6.more_data) {
		talloc_steal(mem_ctx, getnc_state->la_list);

		r->out.ctr->ctr6.new_highwatermark = getnc_state->final_hwm;
		r->out.ctr->ctr6.uptodateness_vector = talloc_move(mem_ctx,
							&getnc_state->final_udv);

		talloc_free(getnc_state);
		b_state->getncchanges_state = NULL;
	} else {
		ret = drsuapi_DsReplicaHighWaterMark_cmp(&r->out.ctr->ctr6.old_highwatermark,
							 &r->out.ctr->ctr6.new_highwatermark);
		if (ret == 0) {
			/*
			 * We need to make sure that we never return the
			 * same highwatermark within the same replication
			 * cycle more than once. Otherwise we cannot detect
			 * when the client uses an unexptected highwatermark.
			 *
			 * This is a HACK which is needed because our
			 * object ordering is wrong and set tmp_highest_usn
			 * to a value that is higher than what we already
			 * sent to the client (destination dsa).
			 */
			r->out.ctr->ctr6.new_highwatermark.reserved_usn += 1;
		}

		getnc_state->last_hwm = r->out.ctr->ctr6.new_highwatermark;
	}

	if (req10->extended_op != DRSUAPI_EXOP_NONE) {
		r->out.ctr->ctr6.uptodateness_vector = NULL;
		r->out.ctr->ctr6.nc_object_count = 0;
		ZERO_STRUCT(r->out.ctr->ctr6.new_highwatermark);
	}

	DEBUG(r->out.ctr->ctr6.more_data?4:2,
	      ("DsGetNCChanges with uSNChanged >= %llu flags 0x%08x on %s gave %u objects (done %u/%u) %u links (done %u/%u (as %s))\n",
	       (unsigned long long)(req10->highwatermark.highest_usn+1),
	       req10->replica_flags, drs_ObjectIdentifier_to_string(mem_ctx, ncRoot),
	       r->out.ctr->ctr6.object_count,
	       i, r->out.ctr->ctr6.more_data?getnc_state->num_records:i,
	       r->out.ctr->ctr6.linked_attributes_count,
	       link_given, link_total,
	       dom_sid_string(mem_ctx, user_sid)));

#if 0
	if (!r->out.ctr->ctr6.more_data && req10->extended_op != DRSUAPI_EXOP_NONE) {
		NDR_PRINT_FUNCTION_DEBUG(drsuapi_DsGetNCChanges, NDR_BOTH, r);
	}
#endif

	return WERR_OK;
}
