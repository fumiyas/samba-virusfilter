/* 
   Unix SMB/CIFS mplementation.

   The module that handles the Schema FSMO Role Owner
   checkings, it also loads the dsdb_schema.
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009-2010

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
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include <tdb.h>
#include "lib/tdb_wrap/tdb_wrap.h"
#include "dsdb/samdb/ldb_modules/util.h"

#include "system/filesys.h"
struct schema_load_private_data {
	struct ldb_module *module;
	bool in_transaction;
	struct tdb_wrap *metadata;
	uint64_t schema_seq_num_cache;
	int tdb_seqnum;
};

static int dsdb_schema_from_db(struct ldb_module *module,
			       TALLOC_CTX *mem_ctx,
			       uint64_t schema_seq_num,
			       struct dsdb_schema **schema);

/*
 * Open sam.ldb.d/metadata.tdb.
 */
static int schema_metadata_open(struct ldb_module *module)
{
	struct schema_load_private_data *data = talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx;
	struct loadparm_context *lp_ctx;
	const char *sam_name;
	char *filename;
	int open_flags;
	struct stat statbuf;

	if (!data) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"schema_load: metadata not initialized");
	}
	data->metadata = NULL;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(module);
	}

	sam_name = (const char *)ldb_get_opaque(ldb, "ldb_url");
	if (!sam_name) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	if (strncmp("tdb://", sam_name, 6) == 0) {
		sam_name += 6;
	}
	filename = talloc_asprintf(tmp_ctx, "%s.d/metadata.tdb", sam_name);
	if (!filename) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	open_flags = O_RDWR;
	if (stat(filename, &statbuf) != 0) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lp_ctx = talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"),
				       struct loadparm_context);

	data->metadata = tdb_wrap_open(data, filename, 10,
				       lpcfg_tdb_flags(lp_ctx, TDB_DEFAULT|TDB_SEQNUM),
				       open_flags, 0660);
	if (data->metadata == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

static int schema_metadata_get_uint64(struct schema_load_private_data *data,
					 const char *key, uint64_t *value,
					 uint64_t default_value)
{
	struct tdb_context *tdb;
	TDB_DATA tdb_key, tdb_data;
	char *value_str;
	TALLOC_CTX *tmp_ctx;
	int tdb_seqnum;

	if (!data) {
		*value = default_value;
		return LDB_SUCCESS;
	}

	if (!data->metadata) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	tdb_seqnum = tdb_get_seqnum(data->metadata->tdb);
	if (tdb_seqnum == data->tdb_seqnum) {
		*value = data->schema_seq_num_cache;
		return LDB_SUCCESS;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(data->module);
	}

	tdb = data->metadata->tdb;

	tdb_key.dptr = (uint8_t *)discard_const_p(char, key);
	tdb_key.dsize = strlen(key);

	tdb_data = tdb_fetch(tdb, tdb_key);
	if (!tdb_data.dptr) {
		if (tdb_error(tdb) == TDB_ERR_NOEXIST) {
			*value = default_value;
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		} else {
			talloc_free(tmp_ctx);
			return ldb_module_error(data->module, LDB_ERR_OPERATIONS_ERROR,
						tdb_errorstr(tdb));
		}
	}

	value_str = talloc_strndup(tmp_ctx, (char *)tdb_data.dptr, tdb_data.dsize);
	if (value_str == NULL) {
		SAFE_FREE(tdb_data.dptr);
		talloc_free(tmp_ctx);
		return ldb_module_oom(data->module);
	}

	/*
	 * Now store it in the cache.  We don't mind that tdb_seqnum
	 * may be stale now, that just means the cache won't be used
	 * next time
	 */
	data->tdb_seqnum = tdb_seqnum;
	data->schema_seq_num_cache = strtoull(value_str, NULL, 10);

	*value = data->schema_seq_num_cache;

	SAFE_FREE(tdb_data.dptr);
	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}

static struct dsdb_schema *dsdb_schema_refresh(struct ldb_module *module, struct tevent_context *ev,
					       struct dsdb_schema *schema, bool is_global_schema)
{
	TALLOC_CTX *mem_ctx;
	uint64_t schema_seq_num = 0;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_schema *new_schema;
	
	struct schema_load_private_data *private_data = talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	if (!private_data) {
		/* We can't refresh until the init function has run */
		return schema;
	}

	/* We don't allow a schema reload during a transaction - nobody else can modify our schema behind our backs */
	if (private_data->in_transaction) {
		return schema;
	}

	SMB_ASSERT(ev == ldb_get_event_context(ldb));

	mem_ctx = talloc_new(module);
	if (mem_ctx == NULL) {
		return NULL;
	}

	/*
	 * We update right now the last refresh timestamp so that if
	 * the schema partition hasn't change we don't keep on retrying.
	 * Otherwise if the timestamp was update only when the schema has
	 * actually changed (and therefor completely reloaded) we would
	 * continue to hit the database to get the highest USN.
	 */

	ret = schema_metadata_get_uint64(private_data, DSDB_METADATA_SCHEMA_SEQ_NUM, &schema_seq_num, 0);

	if (schema != NULL) {
		if (ret == LDB_SUCCESS) {
			if (schema->metadata_usn == schema_seq_num) {
				TALLOC_FREE(mem_ctx);
				return schema;
			} else {
				DEBUG(3, ("Schema refresh needed %lld != %lld\n",
					  (unsigned long long)schema->metadata_usn,
					  (unsigned long long)schema_seq_num));
			}
		} else {
			/* From an old provision it can happen that the tdb didn't exists yet */
			DEBUG(0, ("Error while searching for the schema usn in the metadata ignoring: %d:%s:%s\n",
			      ret, ldb_strerror(ret), ldb_errstring(ldb)));
			TALLOC_FREE(mem_ctx);
			return schema;
		}
	} else {
		DEBUG(10, ("Initial schema load needed, as we have no existing schema, seq_num: %lld\n",
			  (unsigned long long)schema_seq_num));
	}

	ret = dsdb_schema_from_db(module, mem_ctx, schema_seq_num, &new_schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "dsdb_schema_from_db() failed: %d:%s: %s",
			      ret, ldb_strerror(ret), ldb_errstring(ldb));
		TALLOC_FREE(mem_ctx);
		return schema;
	}

	ret = dsdb_set_schema(ldb, new_schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "dsdb_set_schema() failed: %d:%s: %s",
			      ret, ldb_strerror(ret), ldb_errstring(ldb));
		TALLOC_FREE(mem_ctx);
		return schema;
	}
	if (is_global_schema) {
		dsdb_make_schema_global(ldb, new_schema);
	}
	TALLOC_FREE(mem_ctx);
	return new_schema;
}


/*
  Given an LDB module (pointing at the schema DB), and the DN, set the populated schema
*/

static int dsdb_schema_from_db(struct ldb_module *module,
			       TALLOC_CTX *mem_ctx,
			       uint64_t schema_seq_num,
			       struct dsdb_schema **schema)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx;
	char *error_string;
	int ret;
	struct ldb_dn *schema_dn = ldb_get_schema_basedn(ldb);
	struct ldb_result *schema_res;
	struct ldb_result *res;
	static const char *schema_attrs[] = {
		"prefixMap",
		"schemaInfo",
		"fSMORoleOwner",
		NULL
	};
	unsigned flags;

	tmp_ctx = talloc_new(module);
	if (!tmp_ctx) {
		return ldb_oom(ldb);
	}

	/* we don't want to trace the schema load */
	flags = ldb_get_flags(ldb);
	ldb_set_flags(ldb, flags & ~LDB_FLG_ENABLE_TRACING);

	/*
	 * setup the prefix mappings and schema info
	 */
	ret = dsdb_module_search_dn(module, tmp_ctx, &schema_res,
				    schema_dn, schema_attrs,
				    DSDB_FLAG_NEXT_MODULE, NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ldb_reset_err_string(ldb);
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "schema_load_init: no schema head present: (skip schema loading)\n");
		goto failed;
	} else if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema: failed to search the schema head: %s",
				       ldb_errstring(ldb));
		goto failed;
	}

	/*
	 * load the attribute definitions
	 */
	ret = dsdb_module_search(module, tmp_ctx, &res,
				 schema_dn, LDB_SCOPE_ONELEVEL, NULL,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				 NULL,
				 "(|(objectClass=attributeSchema)(objectClass=classSchema))");
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema: failed to search attributeSchema and classSchema objects: %s",
				       ldb_errstring(ldb));
		goto failed;
	}

	ret = dsdb_schema_from_ldb_results(tmp_ctx, ldb,
					   schema_res, res, schema, &error_string);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema load failed: %s",
				       error_string);
		goto failed;
	}

	(*schema)->metadata_usn = schema_seq_num;

	talloc_steal(mem_ctx, *schema);

failed:
	if (flags & LDB_FLG_ENABLE_TRACING) {
		flags = ldb_get_flags(ldb);
		ldb_set_flags(ldb, flags | LDB_FLG_ENABLE_TRACING);
	}
	talloc_free(tmp_ctx);
	return ret;
}	


static int schema_load_init(struct ldb_module *module)
{
	struct schema_load_private_data *private_data;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_schema *schema;
	void *readOnlySchema;
	int ret, metadata_ret;

	private_data = talloc_zero(module, struct schema_load_private_data);
	if (private_data == NULL) {
		return ldb_oom(ldb);
	}
	private_data->module = module;
	
	ldb_module_set_private(module, private_data);

	ret = ldb_next_init(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	schema = dsdb_get_schema(ldb, NULL);

	metadata_ret = schema_metadata_open(module);

	/* We might already have a schema */
	if (schema != NULL) {
		/* If we have the metadata.tdb, then hook up the refresh function */
		if (metadata_ret == LDB_SUCCESS && dsdb_uses_global_schema(ldb)) {
			ret = dsdb_set_schema_refresh_function(ldb, dsdb_schema_refresh, module);

			if (ret != LDB_SUCCESS) {
				ldb_debug_set(ldb, LDB_DEBUG_FATAL,
					      "schema_load_init: dsdb_set_schema_refresh_fns() failed: %d:%s: %s",
					      ret, ldb_strerror(ret), ldb_errstring(ldb));
				return ret;
			}
		}

		return LDB_SUCCESS;
	}

	readOnlySchema = ldb_get_opaque(ldb, "readOnlySchema");

	/* If we have the readOnlySchema opaque, then don't check for
	 * runtime schema updates, as they are not permitted (we would
	 * have to update the backend server schema too */
	if (readOnlySchema != NULL) {
		struct dsdb_schema *new_schema;
		ret = dsdb_schema_from_db(module, private_data, 0, &new_schema);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "schema_load_init: dsdb_schema_from_db() failed: %d:%s: %s",
				      ret, ldb_strerror(ret), ldb_errstring(ldb));
			return ret;
		}

		/* "dsdb_set_schema()" steals schema into the ldb_context */
		ret = dsdb_set_schema(ldb, new_schema);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "schema_load_init: dsdb_set_schema() failed: %d:%s: %s",
				      ret, ldb_strerror(ret), ldb_errstring(ldb));
			return ret;
		}

	} else if (metadata_ret == LDB_SUCCESS) {
		ret = dsdb_set_schema_refresh_function(ldb, dsdb_schema_refresh, module);

		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "schema_load_init: dsdb_set_schema_refresh_fns() failed: %d:%s: %s",
				      ret, ldb_strerror(ret), ldb_errstring(ldb));
			return ret;
		}
	} else {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: failed to open metadata.tdb");
		return metadata_ret;
	}

	schema = dsdb_get_schema(ldb, NULL);

	/* We do this, invoking the refresh handler, so we know that it works */
	if (schema == NULL) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: dsdb_get_schema failed");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ret;
}

static int schema_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	/* Try the schema refresh now */
	dsdb_get_schema(ldb, NULL);

	return ldb_next_request(module, req);
}

static int schema_load_start_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_schema *schema;

	/* Try the schema refresh now */
	schema = dsdb_get_schema(ldb, NULL);
	if (schema == NULL) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: dsdb_get_schema failed");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	private_data->in_transaction = true;

	return ldb_next_start_trans(module);
}

static int schema_load_end_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);

	private_data->in_transaction = false;

	return ldb_next_end_trans(module);
}

static int schema_load_del_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);

	private_data->in_transaction = false;

	return ldb_next_del_trans(module);
}

static int schema_load_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_SCHEMA_UPDATE_NOW_OID) != 0) {
		return ldb_next_request(module, req);
	}
	/* Force a refresh */
	dsdb_get_schema(ldb, NULL);

	/* Pass to next module, the partition one should finish the chain */
	return ldb_next_request(module, req);
}


static const struct ldb_module_ops ldb_schema_load_module_ops = {
	.name		= "schema_load",
	.init_context	= schema_load_init,
	.extended	= schema_load_extended,
	.search		= schema_search,
	.start_transaction = schema_load_start_transaction,
	.end_transaction   = schema_load_end_transaction,
	.del_transaction   = schema_load_del_transaction,
};

int ldb_schema_load_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_schema_load_module_ops);
}
