/*
   Unix SMB/CIFS implementation.

   Python DNS server wrapper

   Copyright (C) 2015 Andrew Bartlett

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

#include <Python.h>
#include "includes.h"
#include <pyldb.h>
#include <pytalloc.h>
#include "dns_server/dnsserver_common.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "librpc/rpc/pyrpc_util.h"

/* FIXME: These should be in a header file somewhere */
#define PyErr_LDB_OR_RAISE(py_ldb, ldb) \
	if (!py_check_dcerpc_type(py_ldb, "ldb", "Ldb")) { \
		PyErr_SetString(py_ldb_get_exception(), "Ldb connection object required"); \
		return NULL; \
	} \
	ldb = pyldb_Ldb_AsLdbContext(py_ldb);

#define PyErr_LDB_DN_OR_RAISE(py_ldb_dn, dn) \
	if (!py_check_dcerpc_type(py_ldb_dn, "ldb", "Dn")) { \
		PyErr_SetString(py_ldb_get_exception(), "ldb Dn object required"); \
		return NULL; \
	} \
	dn = pyldb_Dn_AsDn(py_ldb_dn);

static PyObject *py_ldb_get_exception(void)
{
	PyObject *mod = PyImport_ImportModule("ldb");
	if (mod == NULL)
		return NULL;

	return PyObject_GetAttrString(mod, "LdbError");
}

static PyObject *py_dnsp_DnssrvRpcRecord_get_list(struct dnsp_DnssrvRpcRecord *records,
						  uint16_t num_records)
{
	PyObject *py_dns_list;
	int i;
	py_dns_list = PyList_New(num_records);
	if (py_dns_list == NULL) {
		return NULL;
	}
	for (i = 0; i < num_records; i++) {
		PyObject *py_dns_record;
		py_dns_record = py_return_ndr_struct("samba.dcerpc.dnsp", "DnssrvRpcRecord", records, &records[i]);
		PyList_SetItem(py_dns_list, i, py_dns_record);
	}
	return py_dns_list;
}

static int py_dnsp_DnssrvRpcRecord_get_array(PyObject *value,
					     TALLOC_CTX *mem_ctx,
					     struct dnsp_DnssrvRpcRecord **records,
					     uint16_t *num_records)
{
	int i;
	struct dnsp_DnssrvRpcRecord *recs;
	PY_CHECK_TYPE(&PyList_Type, value, return -1;);
	recs = talloc_array(mem_ctx, struct dnsp_DnssrvRpcRecord,
			    PyList_GET_SIZE(value));
	if (recs == NULL) {
		PyErr_NoMemory();
		return -1;
	}
	for (i = 0; i < PyList_GET_SIZE(value); i++) {
		bool type_correct;
		PyObject *item = PyList_GET_ITEM(value, i);
		type_correct = py_check_dcerpc_type(item, "samba.dcerpc.dnsp", "DnssrvRpcRecord");
		if (type_correct == false) {
			return -1;
		}
		if (talloc_reference(mem_ctx, pytalloc_get_mem_ctx(item)) == NULL) {
			PyErr_NoMemory();
			return -1;
		}
		recs[i] = *(struct dnsp_DnssrvRpcRecord *)pytalloc_get_ptr(item);
	}
	*records = recs;
	*num_records = PyList_GET_SIZE(value);
	return 0;
}

static PyObject *py_dsdb_dns_lookup(PyObject *self, PyObject *args)
{
	struct ldb_context *samdb;
	PyObject *py_ldb;
	char *dns_name;
	TALLOC_CTX *frame;
	NTSTATUS status;
	WERROR werr;
	struct dns_server_zone *zones_list;
	struct ldb_dn *dn;
	struct dnsp_DnssrvRpcRecord *records;
	uint16_t num_records;

	if (!PyArg_ParseTuple(args, "Os", &py_ldb, &dns_name)) {
		return NULL;
	}
	PyErr_LDB_OR_RAISE(py_ldb, samdb);

	frame = talloc_stackframe();

	status = dns_common_zones(samdb, frame, &zones_list);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	werr = dns_common_name2dn(samdb, zones_list, frame, dns_name, &dn);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR(werr);
		return NULL;
	}

	werr = dns_common_lookup(samdb,
				 frame,
				 dn,
				 &records,
				 &num_records,
				 NULL);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR(werr);
		return NULL;
	}

	return py_dnsp_DnssrvRpcRecord_get_list(records, num_records);
}

static PyObject *py_dsdb_dns_extract(PyObject *self, PyObject *args)
{
	PyObject *py_dns_el;
	TALLOC_CTX *frame;
	WERROR werr;
	struct ldb_message_element *dns_el;
	struct dnsp_DnssrvRpcRecord *records;
	uint16_t num_records;

	if (!PyArg_ParseTuple(args, "O", &py_dns_el)) {
		return NULL;
	}

	if (!py_check_dcerpc_type(py_dns_el, "ldb", "MessageElement")) {
		PyErr_SetString(py_ldb_get_exception(),
				"ldb MessageElement object required");
		return NULL;
	}
	dns_el = pyldb_MessageElement_AsMessageElement(py_dns_el);

	frame = talloc_stackframe();

	werr = dns_common_extract(dns_el,
				  frame,
				  &records,
				  &num_records);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR(werr);
		return NULL;
	}

	return py_dnsp_DnssrvRpcRecord_get_list(records, num_records);
}

static PyObject *py_dsdb_dns_replace(PyObject *self, PyObject *args)
{
	struct ldb_context *samdb;
	PyObject *py_ldb, *py_dns_records;
	char *dns_name;
	TALLOC_CTX *frame;
	NTSTATUS status;
	WERROR werr;
	int ret;
	struct dns_server_zone *zones_list;
	struct ldb_dn *dn;
	struct dnsp_DnssrvRpcRecord *records;
	uint16_t num_records;

	/*
	 * TODO: This is a shocking abuse, but matches what the
	 * internal DNS server does, it should be pushed into
	 * dns_common_replace()
	 */
	static const int serial = 110;

	if (!PyArg_ParseTuple(args, "OsO", &py_ldb, &dns_name, &py_dns_records)) {
		return NULL;
	}
	PyErr_LDB_OR_RAISE(py_ldb, samdb);

	frame = talloc_stackframe();

	status = dns_common_zones(samdb, frame, &zones_list);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	werr = dns_common_name2dn(samdb, zones_list, frame, dns_name, &dn);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR(werr);
		return NULL;
	}

	ret = py_dnsp_DnssrvRpcRecord_get_array(py_dns_records,
						frame,
						&records, &num_records);
	if (ret != 0) {
		return NULL;
	}

	werr = dns_common_replace(samdb,
				  frame,
				  dn,
				  false, /* Not adding a record */
				  serial,
				  records,
				  num_records);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR(werr);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_dns_replace_by_dn(PyObject *self, PyObject *args)
{
	struct ldb_context *samdb;
	PyObject *py_ldb, *py_dn, *py_dns_records;
	TALLOC_CTX *frame;
	WERROR werr;
	int ret;
	struct ldb_dn *dn;
	struct dnsp_DnssrvRpcRecord *records;
	uint16_t num_records;

	/*
	 * TODO: This is a shocking abuse, but matches what the
	 * internal DNS server does, it should be pushed into
	 * dns_common_replace()
	 */
	static const int serial = 110;

	if (!PyArg_ParseTuple(args, "OOO", &py_ldb, &py_dn, &py_dns_records)) {
		return NULL;
	}
	PyErr_LDB_OR_RAISE(py_ldb, samdb);

	PyErr_LDB_DN_OR_RAISE(py_dn, dn);

	frame = talloc_stackframe();

	ret = py_dnsp_DnssrvRpcRecord_get_array(py_dns_records,
						frame,
						&records, &num_records);
	if (ret != 0) {
		return NULL;
	}

	werr = dns_common_replace(samdb,
				  frame,
				  dn,
				  false, /* Not adding a record */
				  serial,
				  records,
				  num_records);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR(werr);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMethodDef py_dsdb_dns_methods[] = {

	{ "lookup", (PyCFunction)py_dsdb_dns_lookup,
		METH_VARARGS, "Get the DNS database entries for a DNS name"},
	{ "replace", (PyCFunction)py_dsdb_dns_replace,
		METH_VARARGS, "Replace the DNS database entries for a DNS name"},
	{ "replace_by_dn", (PyCFunction)py_dsdb_dns_replace_by_dn,
		METH_VARARGS, "Replace the DNS database entries for a LDB DN"},
	{ "extract", (PyCFunction)py_dsdb_dns_extract,
		METH_VARARGS, "Return the DNS database entry as a python structure from an Ldb.MessageElement of type dnsRecord"},
	{ NULL }
};

void initdsdb_dns(void);

void initdsdb_dns(void)
{
	PyObject *m;

	m = Py_InitModule3("dsdb_dns", py_dsdb_dns_methods,
			   "Python bindings for the DNS objects in the directory service databases.");
	if (m == NULL)
		return;
}
