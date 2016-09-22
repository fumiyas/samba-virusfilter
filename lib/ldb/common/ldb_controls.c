/* 
   ldb database library

   Copyright (C) Simo Sorce  2005

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

/*
 *  Name: ldb_controls.c
 *
 *  Component: ldb controls utility functions
 *
 *  Description: helper functions for control modules
 *
 *  Author: Simo Sorce
 */

#include "ldb_private.h"

/* check if a control with the specified "oid" exist and return it */
/* returns NULL if not found */
struct ldb_control *ldb_request_get_control(struct ldb_request *req, const char *oid)
{
	unsigned int i;

	if (req->controls != NULL) {
		for (i = 0; req->controls[i]; i++) {
			if (req->controls[i]->oid && strcmp(oid, req->controls[i]->oid) == 0) {
				break;
			}
		}

		return req->controls[i];
	}

	return NULL;
}

/* check if a control with the specified "oid" exist and return it */
/* returns NULL if not found */
struct ldb_control *ldb_reply_get_control(struct ldb_reply *rep, const char *oid)
{
	unsigned int i;

	if (rep->controls != NULL) {
		for (i = 0; rep->controls[i]; i++) {
			if (rep->controls[i]->oid && strcmp(oid, rep->controls[i]->oid) == 0) {
				break;
			}
		}

		return rep->controls[i];
	}

	return NULL;
}

/*
 * Saves the current controls list into the "saver" (can also be NULL) and
 * replace the one in "req" with a new one excluding the "exclude" control
 * (if it is NULL then the list remains the same)
 *
 * Returns 0 on error.
 */
int ldb_save_controls(struct ldb_control *exclude, struct ldb_request *req, struct ldb_control ***saver)
{
	struct ldb_control **lcs, **lcs_old;
	unsigned int i, j;

	lcs_old = req->controls;
	if (saver != NULL) {
		*saver = lcs_old;
	}

	for (i = 0; req->controls && req->controls[i]; i++);
	if (i == 0) {
		req->controls = NULL;
		return 1;
	}

	lcs = talloc_array(req, struct ldb_control *, i + 1);
	if (!lcs) {
		return 0;
	}

	for (i = 0, j = 0; lcs_old[i]; i++) {
		if (exclude == lcs_old[i]) continue;
		lcs[j] = lcs_old[i];
		j++;
	}
	lcs[j] = NULL;

	req->controls = talloc_realloc(req, lcs, struct ldb_control *, j + 1);
	if (req->controls == NULL) {
		return 0;
	}
	return 1;
}

/*
 * Returns a list of controls, except the one specified with "exclude" (can
 * also be NULL).  Included controls become a child of returned list if they
 * were children of "controls_in".
 *
 * Returns NULL on error (OOM) or an empty control list.
 */
struct ldb_control **ldb_controls_except_specified(struct ldb_control **controls_in, 
					       TALLOC_CTX *mem_ctx, 
					       struct ldb_control *exclude)
{
	struct ldb_control **lcs = NULL;
	unsigned int i, j, n;

	for (i = 0; controls_in && controls_in[i]; i++);
	if (i == 0) {
		return NULL;
	}
	n = i;

	for (i = 0, j = 0; controls_in && controls_in[i]; i++) {
		if (exclude == controls_in[i]) continue;

		if (!lcs) {
			/* Allocate here so if we remove the only
			 * control, or there were no controls, we
			 * don't allocate at all, and just return
			 * NULL */
			lcs = talloc_array(mem_ctx, struct ldb_control *,
					   n + 1);
			if (!lcs) {
				return NULL;
			}
		}

		lcs[j] = controls_in[i];
		talloc_reparent(controls_in, lcs, lcs[j]);
		j++;
	}
	if (lcs) {
		lcs[j] = NULL;

		lcs = talloc_realloc(mem_ctx, lcs, struct ldb_control *, j + 1);
	}

	return lcs;
}

/* check if there's any control marked as critical in the list */
/* return True if any, False if none */
int ldb_check_critical_controls(struct ldb_control **controls)
{
	unsigned int i;

	if (controls == NULL) {
		return 0;
	}

	for (i = 0; controls[i]; i++) {
		if (controls[i]->critical) {
			return 1;
		}
	}

	return 0;
}

int ldb_request_add_control(struct ldb_request *req, const char *oid, bool critical, void *data)
{
	unsigned int i, n;
	struct ldb_control **ctrls;
	struct ldb_control *ctrl;

	for (n=0; req->controls && req->controls[n];n++) { 
		/* having two controls of the same OID makes no sense */
		if (req->controls[n]->oid && strcmp(oid, req->controls[n]->oid) == 0) {
			return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
		}
	}

	ctrls = talloc_array(req,
			       struct ldb_control *,
			       n + 2);
	if (!ctrls) return LDB_ERR_OPERATIONS_ERROR;

	for (i=0; i<n; i++) {
		ctrls[i] = req->controls[i];
	}

	req->controls = ctrls;
	ctrls[n] = NULL;
	ctrls[n+1] = NULL;

	ctrl = talloc(ctrls, struct ldb_control);
	if (!ctrl) return LDB_ERR_OPERATIONS_ERROR;

	ctrl->oid	= talloc_strdup(ctrl, oid);
	if (!ctrl->oid) return LDB_ERR_OPERATIONS_ERROR;
	ctrl->critical	= critical;
	ctrl->data	= data;

	ctrls[n] = ctrl;
	return LDB_SUCCESS;
}

int ldb_reply_add_control(struct ldb_reply *ares, const char *oid, bool critical, void *data)
{
	unsigned n;
	struct ldb_control **ctrls;
	struct ldb_control *ctrl;

	for (n=0; ares->controls && ares->controls[n];) { 
		/* having two controls of the same OID makes no sense */
		if (ares->controls[n]->oid && strcmp(oid, ares->controls[n]->oid) == 0) {
			return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
		}
		n++; 
	}

	ctrls = talloc_realloc(ares, ares->controls,
			       struct ldb_control *,
			       n + 2);
	if (!ctrls) return LDB_ERR_OPERATIONS_ERROR;
	ares->controls = ctrls;
	ctrls[n] = NULL;
	ctrls[n+1] = NULL;

	ctrl = talloc(ctrls, struct ldb_control);
	if (!ctrl) return LDB_ERR_OPERATIONS_ERROR;

	ctrl->oid	= talloc_strdup(ctrl, oid);
	if (!ctrl->oid) return LDB_ERR_OPERATIONS_ERROR;
	ctrl->critical	= critical;
	ctrl->data	= data;

	ctrls[n] = ctrl;
	return LDB_SUCCESS;
}

/* Add a control to the request, replacing the old one if it is already in the request */
int ldb_request_replace_control(struct ldb_request *req, const char *oid, bool critical, void *data)
{
	unsigned int n;
	int ret;

	ret = ldb_request_add_control(req, oid, critical, data);
	if (ret != LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS) {
		return ret;
	}

	for (n=0; req->controls[n];n++) {
		if (req->controls[n]->oid && strcmp(oid, req->controls[n]->oid) == 0) {
			req->controls[n]->critical = critical;
			req->controls[n]->data = data;
			return LDB_SUCCESS;
		}
	}

	return LDB_ERR_OPERATIONS_ERROR;
}

/*
 * Return a control as string
 * the project (ie. name:value1:value2:...:valuen
 * The string didn't include the criticity of the critical flag
 */
char *ldb_control_to_string(TALLOC_CTX *mem_ctx, const struct ldb_control *control)
{
	char *res = NULL;

	if (strcmp(control->oid, LDB_CONTROL_PAGED_RESULTS_OID) == 0) {
		struct ldb_paged_control *rep_control = talloc_get_type(control->data, struct ldb_paged_control);
		char *cookie;

		cookie = ldb_base64_encode(mem_ctx, rep_control->cookie, rep_control->cookie_len);
		if (cookie == NULL) {
			return NULL;
		}
		if (cookie[0] != '\0') {
			res = talloc_asprintf(mem_ctx, "%s:%d:%s",
						LDB_CONTROL_PAGED_RESULTS_NAME,
						control->critical,
						cookie);

			talloc_free(cookie);
		} else {
			res = talloc_asprintf(mem_ctx, "%s:%d",
						LDB_CONTROL_PAGED_RESULTS_NAME,
						control->critical);
		}
		return res;
	}

	if (strcmp(control->oid, LDB_CONTROL_VLV_RESP_OID) == 0) {
		struct ldb_vlv_resp_control *rep_control = talloc_get_type(control->data,
								struct ldb_vlv_resp_control);

		char *cookie;

		cookie = ldb_base64_encode(mem_ctx,
					   (char *)rep_control->contextId,
					   rep_control->ctxid_len);
		if (cookie == NULL) {
			return NULL;
		}

		res = talloc_asprintf(mem_ctx, "%s:%d:%d:%d:%d:%s",
						LDB_CONTROL_VLV_RESP_NAME,
						control->critical,
						rep_control->targetPosition,
						rep_control->contentCount,
						rep_control->vlv_result,
				                cookie);

		return res;
	}

	if (strcmp(control->oid, LDB_CONTROL_SORT_RESP_OID) == 0) {
		struct ldb_sort_resp_control *rep_control = talloc_get_type(control->data,
								struct ldb_sort_resp_control);

		res = talloc_asprintf(mem_ctx, "%s:%d:%d:%s",
					LDB_CONTROL_SORT_RESP_NAME,
					control->critical,
					rep_control->result,
					rep_control->attr_desc);

		return res;
	}

	if (strcmp(control->oid, LDB_CONTROL_ASQ_OID) == 0) {
		struct ldb_asq_control *rep_control = talloc_get_type(control->data,
								struct ldb_asq_control);

		res = talloc_asprintf(mem_ctx, "%s:%d:%d",
					LDB_CONTROL_SORT_RESP_NAME,
					control->critical,
					rep_control->result);

		return res;
	}

	if (strcmp(control->oid, LDB_CONTROL_DIRSYNC_OID) == 0) {
		char *cookie;
		struct ldb_dirsync_control *rep_control = talloc_get_type(control->data,
								struct ldb_dirsync_control);

		cookie = ldb_base64_encode(mem_ctx, rep_control->cookie,
				rep_control->cookie_len);
		if (cookie == NULL) {
			return NULL;
		}
		res = talloc_asprintf(mem_ctx, "%s:%d:%d:%d:%s",
					LDB_CONTROL_DIRSYNC_NAME,
					control->critical,
					rep_control->flags,
					rep_control->max_attributes,
					cookie);

		talloc_free(cookie);
		return res;
	}
	if (strcmp(control->oid, LDB_CONTROL_DIRSYNC_EX_OID) == 0) {
		char *cookie;
		struct ldb_dirsync_control *rep_control = talloc_get_type(control->data,
								struct ldb_dirsync_control);

		cookie = ldb_base64_encode(mem_ctx, rep_control->cookie,
				rep_control->cookie_len);
		if (cookie == NULL) {
			return NULL;
		}
		res = talloc_asprintf(mem_ctx, "%s:%d:%d:%d:%s",
					LDB_CONTROL_DIRSYNC_EX_NAME,
					control->critical,
					rep_control->flags,
					rep_control->max_attributes,
					cookie);

		talloc_free(cookie);
		return res;
	}

	if (strcmp(control->oid, LDB_CONTROL_VERIFY_NAME_OID) == 0) {
		struct ldb_verify_name_control *rep_control = talloc_get_type(control->data, struct ldb_verify_name_control);

		if (rep_control->gc != NULL) {
			res = talloc_asprintf(mem_ctx, "%s:%d:%d:%s",
						LDB_CONTROL_VERIFY_NAME_NAME,
						control->critical,
						rep_control->flags,
						rep_control->gc);

		} else {
			res = talloc_asprintf(mem_ctx, "%s:%d:%d",
						LDB_CONTROL_VERIFY_NAME_NAME,
						control->critical,
						rep_control->flags);
		}
		return res;
	}

	/*
	 * From here we don't know the control
	 */
	if (control->data == NULL) {
		/*
		 * We don't know the control but there is no real data attached
		 * to it so we can represent it with local_oid:oid:criticity.
		 */
		res = talloc_asprintf(mem_ctx, "local_oid:%s:%d",
					control->oid,
					control->critical);
	} else {
		res = talloc_asprintf(mem_ctx, "unknown oid:%s",
					control->oid);
	}
	return res;
}


/*
 * A little trick to allow one to use constants defined in headers rather than
 * hardwritten in the file.
 * "sizeof" will return the \0 char as well so it will take the place of ":"
 * in the length of the string.
 */
#define LDB_CONTROL_CMP(control, NAME) strncmp(control, NAME ":", sizeof(NAME))

/* Parse one string and return associated control if parsing is successful*/
struct ldb_control *ldb_parse_control_from_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char *control_strings)
{
	struct ldb_control *ctrl;

	if (!(ctrl = talloc(mem_ctx, struct ldb_control))) {
		ldb_oom(ldb);
		return NULL;
	}

	if (LDB_CONTROL_CMP(control_strings,
				LDB_CONTROL_VLV_REQ_NAME) == 0) {
		struct ldb_vlv_req_control *control;
		const char *p;
		char attr[1024];
		char ctxid[1024];
		int crit, bc, ac, os, cc, ret;

		attr[0] = '\0';
		ctxid[0] = '\0';
		p = &(control_strings[sizeof(LDB_CONTROL_VLV_REQ_NAME)]);
		ret = sscanf(p, "%d:%d:%d:%d:%d:%1023[^$]", &crit, &bc, &ac, &os, &cc, ctxid);
		/* We allow 2 ways to encode the GT_EQ case, because the
		   comparison string might contain null bytes or colons, which
		   would break sscanf (or indeed any parsing mechanism). */
		if (ret == 3) {
			ret = sscanf(p, "%d:%d:%d:>=%1023[^:]:%1023[^$]", &crit, &bc, &ac, attr, ctxid);
		}
		if (ret == 3) {
			int len;
			ret = sscanf(p, "%d:%d:%d:base64>=%1023[^:]:%1023[^$]", &crit, &bc, &ac, attr, ctxid);
			len = ldb_base64_decode(attr);
			if (len < 0) {
				ret = -1;
			}
		}

		if ((ret < 4) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid VLV control syntax\n"
					  " syntax: crit(b):bc(n):ac(n):"
					  "{os(n):cc(n)|>=val(s)|base64>=val(o)}[:ctxid(o)]\n"
					  "   note: b = boolean, n = number, s = string, o = b64 binary blob");
			talloc_free(ctrl);
			return NULL;
		}
		ctrl->oid = LDB_CONTROL_VLV_REQ_OID;
		ctrl->critical = crit;
		if (!(control = talloc(ctrl,
					struct ldb_vlv_req_control))) {
			ldb_oom(ldb);
			talloc_free(ctrl);
			return NULL;
		}
		control->beforeCount = bc;
		control->afterCount = ac;
		if (attr[0]) {
			control->type = 1;
			control->match.gtOrEq.value = talloc_strdup(control, attr);
			control->match.gtOrEq.value_len = strlen(attr);
		} else {
			control->type = 0;
			control->match.byOffset.offset = os;
			control->match.byOffset.contentCount = cc;
		}
		if (ctxid[0]) {
			int len = ldb_base64_decode(ctxid);
			if (len < 0) {
				ldb_set_errstring(ldb,
						  "invalid VLV context_id\n");
				talloc_free(ctrl);
				return NULL;
			}
			control->ctxid_len = len;
			control->contextId = talloc_memdup(control, ctxid,
							   control->ctxid_len);
			if (control->contextId == NULL) {
				ldb_oom(ldb);
				return NULL;
			}
		} else {
			control->ctxid_len = 0;
			control->contextId = NULL;
		}
		ctrl->data = control;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_DIRSYNC_NAME) == 0) {
		struct ldb_dirsync_control *control;
		const char *p;
		char cookie[1024];
		int crit, max_attrs, ret;
		uint32_t flags;

		cookie[0] = '\0';
		p = &(control_strings[sizeof(LDB_CONTROL_DIRSYNC_NAME)]);
		ret = sscanf(p, "%d:%u:%d:%1023[^$]", &crit, &flags, &max_attrs, cookie);

		if ((ret < 3) || (crit < 0) || (crit > 1) || (max_attrs < 0)) {
			ldb_set_errstring(ldb,
					  "invalid dirsync control syntax\n"
					  " syntax: crit(b):flags(n):max_attrs(n)[:cookie(o)]\n"
					  "   note: b = boolean, n = number, o = b64 binary blob");
			talloc_free(ctrl);
			return NULL;
		}

		/* w2k3 seems to ignore the parameter,
		 * but w2k sends a wrong cookie when this value is to small
		 * this would cause looping forever, while getting
		 * the same data and same cookie forever
		 */
		if (max_attrs == 0) max_attrs = 0x0FFFFFFF;

		ctrl->oid = LDB_CONTROL_DIRSYNC_OID;
		ctrl->critical = crit;
		control = talloc(ctrl, struct ldb_dirsync_control);
		control->flags = flags;
		control->max_attributes = max_attrs;
		if (*cookie) {
			int len = ldb_base64_decode(cookie);
			if (len < 0) {
				ldb_set_errstring(ldb,
						  "invalid dirsync cookie\n");
				talloc_free(ctrl);
				return NULL;
			}
			control->cookie_len = len;
			control->cookie = (char *)talloc_memdup(control, cookie, control->cookie_len);
			if (control->cookie == NULL) {
				ldb_oom(ldb);
				return NULL;
			}
		} else {
			control->cookie = NULL;
			control->cookie_len = 0;
		}
		ctrl->data = control;

		return ctrl;
	}
	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_DIRSYNC_EX_NAME) == 0) {
		struct ldb_dirsync_control *control;
		const char *p;
		char cookie[1024];
		int crit, max_attrs, ret;
		uint32_t flags;

		cookie[0] = '\0';
		p = &(control_strings[sizeof(LDB_CONTROL_DIRSYNC_EX_NAME)]);
		ret = sscanf(p, "%d:%u:%d:%1023[^$]", &crit, &flags, &max_attrs, cookie);

		if ((ret < 3) || (crit < 0) || (crit > 1) || (max_attrs < 0)) {
			ldb_set_errstring(ldb,
					  "invalid dirsync_ex control syntax\n"
					  " syntax: crit(b):flags(n):max_attrs(n)[:cookie(o)]\n"
					  "   note: b = boolean, n = number, o = b64 binary blob");
			talloc_free(ctrl);
			return NULL;
		}

		/* w2k3 seems to ignore the parameter,
		 * but w2k sends a wrong cookie when this value is to small
		 * this would cause looping forever, while getting
		 * the same data and same cookie forever
		 */
		if (max_attrs == 0) max_attrs = 0x0FFFFFFF;

		ctrl->oid = LDB_CONTROL_DIRSYNC_EX_OID;
		ctrl->critical = crit;
		control = talloc(ctrl, struct ldb_dirsync_control);
		control->flags = flags;
		control->max_attributes = max_attrs;
		if (*cookie) {
			int len = ldb_base64_decode(cookie);
			if (len < 0) {
				ldb_set_errstring(ldb,
						  "invalid dirsync_ex cookie"
						  " (probably too long)\n");
				talloc_free(ctrl);
				return NULL;
			}
			control->cookie_len = len;
			control->cookie = (char *)talloc_memdup(control, cookie, control->cookie_len);
			if (control->cookie == NULL) {
				ldb_oom(ldb);
				return NULL;
			}
		} else {
			control->cookie = NULL;
			control->cookie_len = 0;
		}
		ctrl->data = control;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_ASQ_NAME) == 0) {
		struct ldb_asq_control *control;
		const char *p;
		char attr[256];
		int crit, ret;

		attr[0] = '\0';
		p = &(control_strings[sizeof(LDB_CONTROL_ASQ_NAME)]);
		ret = sscanf(p, "%d:%255[^$]", &crit, attr);
		if ((ret != 2) || (crit < 0) || (crit > 1) || (attr[0] == '\0')) {
			ldb_set_errstring(ldb,
					  "invalid asq control syntax\n"
					  " syntax: crit(b):attr(s)\n"
					  "   note: b = boolean, s = string");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_ASQ_OID;
		ctrl->critical = crit;
		control = talloc(ctrl, struct ldb_asq_control);
		control->request = 1;
		control->source_attribute = talloc_strdup(control, attr);
		control->src_attr_len = strlen(attr);
		ctrl->data = control;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_EXTENDED_DN_NAME) == 0) {
		struct ldb_extended_dn_control *control;
		const char *p;
		int crit, type, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_EXTENDED_DN_NAME)]);
		ret = sscanf(p, "%d:%d", &crit, &type);
		if ((ret != 2) || (crit < 0) || (crit > 1) || (type < 0) || (type > 1)) {
			ret = sscanf(p, "%d", &crit);
			if ((ret != 1) || (crit < 0) || (crit > 1)) {
				ldb_set_errstring(ldb,
						  "invalid extended_dn control syntax\n"
						  " syntax: crit(b)[:type(i)]\n"
						  "   note: b = boolean\n"
						  "         i = integer\n"
						  "   valid values are: 0 - hexadecimal representation\n"
						  "                     1 - normal string representation");
				talloc_free(ctrl);
				return NULL;
			}
			control = NULL;
		} else {
			control = talloc(ctrl, struct ldb_extended_dn_control);
			control->type = type;
		}

		ctrl->oid = LDB_CONTROL_EXTENDED_DN_OID;
		ctrl->critical = crit;
		ctrl->data = talloc_steal(ctrl, control);

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_SD_FLAGS_NAME) == 0) {
		struct ldb_sd_flags_control *control;
		const char *p;
		int crit, ret;
		unsigned secinfo_flags;

		p = &(control_strings[sizeof(LDB_CONTROL_SD_FLAGS_NAME)]);
		ret = sscanf(p, "%d:%u", &crit, &secinfo_flags);
		if ((ret != 2) || (crit < 0) || (crit > 1) || (secinfo_flags > 0xF)) {
			ldb_set_errstring(ldb,
					  "invalid sd_flags control syntax\n"
					  " syntax: crit(b):secinfo_flags(n)\n"
					  "   note: b = boolean, n = number");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_SD_FLAGS_OID;
		ctrl->critical = crit;
		control = talloc(ctrl, struct ldb_sd_flags_control);
		control->secinfo_flags = secinfo_flags;
		ctrl->data = control;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_SEARCH_OPTIONS_NAME) == 0) {
		struct ldb_search_options_control *control;
		const char *p;
		int crit, ret;
		unsigned search_options;

		p = &(control_strings[sizeof(LDB_CONTROL_SEARCH_OPTIONS_NAME)]);
		ret = sscanf(p, "%d:%u", &crit, &search_options);
		if ((ret != 2) || (crit < 0) || (crit > 1) || (search_options > 0xF)) {
			ldb_set_errstring(ldb,
					  "invalid search_options control syntax\n"
					  " syntax: crit(b):search_options(n)\n"
					  "   note: b = boolean, n = number");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_SEARCH_OPTIONS_OID;
		ctrl->critical = crit;
		control = talloc(ctrl, struct ldb_search_options_control);
		control->search_options = search_options;
		ctrl->data = control;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_BYPASS_OPERATIONAL_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_BYPASS_OPERATIONAL_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid bypassopreational control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_BYPASS_OPERATIONAL_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_RELAX_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_RELAX_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid relax control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_RELAX_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_RECALCULATE_SD_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_RECALCULATE_SD_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid recalculate_sd control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_RECALCULATE_SD_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_DOMAIN_SCOPE_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_DOMAIN_SCOPE_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid domain_scope control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_DOMAIN_SCOPE_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_PAGED_RESULTS_NAME) == 0) {
		struct ldb_paged_control *control;
		const char *p;
		char cookie[1024];
		int crit, size, ret;

		cookie[0] = '\0';
		p = &(control_strings[sizeof(LDB_CONTROL_PAGED_RESULTS_NAME)]);
		ret = sscanf(p, "%d:%d:%1023[^$]", &crit, &size, cookie);
		if ((ret < 2) || (ret > 3) || (crit < 0) || (crit > 1) ||
		    (size < 0)) {
			ldb_set_errstring(ldb,
				"invalid paged_results control syntax\n"
				" syntax: crit(b):size(n)[:cookie(base64)]\n"
				"   note: b = boolean, n = number");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_PAGED_RESULTS_OID;
		ctrl->critical = crit;
		control = talloc(ctrl, struct ldb_paged_control);
		control->size = size;
		if (cookie[0] != '\0') {
			int len = ldb_base64_decode(cookie);
			if (len < 0) {
				ldb_set_errstring(ldb,
						  "invalid paged_results cookie"
						  " (probably too long)\n");
				talloc_free(ctrl);
				return NULL;
			}
			control->cookie_len = len;
			control->cookie = talloc_memdup(control, cookie, control->cookie_len);
			if (control->cookie == NULL) {
				ldb_oom(ldb);
				return NULL;
			}
		} else {
			control->cookie = NULL;
			control->cookie_len = 0;
		}
		ctrl->data = control;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_SERVER_SORT_NAME) == 0) {
		struct ldb_server_sort_control **control;
		const char *p;
		char attr[256];
		char rule[128];
		int crit, rev, ret;

		attr[0] = '\0';
		rule[0] = '\0';
		p = &(control_strings[sizeof(LDB_CONTROL_SERVER_SORT_NAME)]);
		ret = sscanf(p, "%d:%d:%255[^:]:%127[^:]", &crit, &rev, attr, rule);
		if ((ret < 3) || (crit < 0) || (crit > 1) || (rev < 0 ) || (rev > 1) ||attr[0] == '\0') {
			ldb_set_errstring(ldb,
					  "invalid server_sort control syntax\n"
					  " syntax: crit(b):rev(b):attr(s)[:rule(s)]\n"
					  "   note: b = boolean, s = string");
			talloc_free(ctrl);
			return NULL;
		}
		ctrl->oid = LDB_CONTROL_SERVER_SORT_OID;
		ctrl->critical = crit;
		control = talloc_array(ctrl, struct ldb_server_sort_control *, 2);
		control[0] = talloc(control, struct ldb_server_sort_control);
		control[0]->attributeName = talloc_strdup(control, attr);
		if (rule[0])
			control[0]->orderingRule = talloc_strdup(control, rule);
		else
			control[0]->orderingRule = NULL;
		control[0]->reverse = rev;
		control[1] = NULL;
		ctrl->data = control;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_NOTIFICATION_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_NOTIFICATION_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid notification control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_NOTIFICATION_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_TREE_DELETE_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_TREE_DELETE_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid tree_delete control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_TREE_DELETE_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_SHOW_DELETED_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_SHOW_DELETED_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid show_deleted control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_SHOW_DELETED_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_SHOW_DEACTIVATED_LINK_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_SHOW_DEACTIVATED_LINK_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid show_deactivated_link control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_SHOW_DEACTIVATED_LINK_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_SHOW_RECYCLED_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_SHOW_RECYCLED_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid show_recycled control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_SHOW_RECYCLED_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_PERMISSIVE_MODIFY_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_PERMISSIVE_MODIFY_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid permissive_modify control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_PERMISSIVE_MODIFY_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_REVEAL_INTERNALS_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_REVEAL_INTERNALS_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid reveal_internals control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_REVEAL_INTERNALS;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (strncmp(control_strings, "local_oid:", 10) == 0) {
		const char *p;
		int crit = 0, ret = 0;
		char oid[256];

		oid[0] = '\0';
		p = &(control_strings[10]);
		ret = sscanf(p, "%255[^:]:%d", oid, &crit);

		if ((ret != 2) || strlen(oid) == 0 || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid local_oid control syntax\n"
					  " syntax: oid(s):crit(b)\n"
					  "   note: b = boolean, s = string");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = talloc_strdup(ctrl, oid);
		if (!ctrl->oid) {
			ldb_oom(ldb);
			talloc_free(ctrl);
			return NULL;
		}
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_RODC_DCPROMO_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_RODC_DCPROMO_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid rodc_join control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_RODC_DCPROMO_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}

	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_PROVISION_NAME) == 0) {
		const char *p;
		int crit, ret;

		p = &(control_strings[sizeof(LDB_CONTROL_PROVISION_NAME)]);
		ret = sscanf(p, "%d", &crit);
		if ((ret != 1) || (crit < 0) || (crit > 1)) {
			ldb_set_errstring(ldb,
					  "invalid provision control syntax\n"
					  " syntax: crit(b)\n"
					  "   note: b = boolean");
			talloc_free(ctrl);
			return NULL;
		}

		ctrl->oid = LDB_CONTROL_PROVISION_OID;
		ctrl->critical = crit;
		ctrl->data = NULL;

		return ctrl;
	}
	if (LDB_CONTROL_CMP(control_strings, LDB_CONTROL_VERIFY_NAME_NAME) == 0) {
		const char *p;
		char gc[1024];
		int crit, flags, ret;
		struct ldb_verify_name_control *control;

		gc[0] = '\0';

		p = &(control_strings[sizeof(LDB_CONTROL_VERIFY_NAME_NAME)]);
		ret = sscanf(p, "%d:%d:%1023[^$]", &crit, &flags, gc);
		if ((ret != 3) || (crit < 0) || (crit > 1)) {
			ret = sscanf(p, "%d:%d", &crit, &flags);
			if ((ret != 2) || (crit < 0) || (crit > 1)) {
				ldb_set_errstring(ldb,
						  "invalid verify_name control syntax\n"
						  " syntax: crit(b):flags(i)[:gc(s)]\n"
						  "   note: b = boolean"
						  "   note: i = integer"
						  "   note: s = string");
				talloc_free(ctrl);
				return NULL;
			}
		}

		ctrl->oid = LDB_CONTROL_VERIFY_NAME_OID;
		ctrl->critical = crit;
		control = talloc(ctrl, struct ldb_verify_name_control);
		control->gc = talloc_strdup(control, gc);
		control->gc_len = strlen(gc);
		control->flags = flags;
		ctrl->data = control;
		return ctrl;
	}
	/*
	 * When no matching control has been found.
	 */
	return NULL;
}

/* Parse controls from the format used on the command line and in ejs */
struct ldb_control **ldb_parse_control_strings(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char **control_strings)
{
	unsigned int i;
	struct ldb_control **ctrl;

	if (control_strings == NULL || control_strings[0] == NULL)
		return NULL;

	for (i = 0; control_strings[i]; i++);

	ctrl = talloc_array(mem_ctx, struct ldb_control *, i + 1);

	ldb_reset_err_string(ldb);
	for (i = 0; control_strings[i]; i++) {
		ctrl[i] = ldb_parse_control_from_string(ldb, ctrl, control_strings[i]);
		if (ctrl[i] == NULL) {
			if (ldb_errstring(ldb) == NULL) {
				/* no controls matched, throw an error */
				ldb_asprintf_errstring(ldb, "Invalid control name: '%s'", control_strings[i]);
			}
			talloc_free(ctrl);
			return NULL;
		}
	}

	ctrl[i] = NULL;

	return ctrl;
}


