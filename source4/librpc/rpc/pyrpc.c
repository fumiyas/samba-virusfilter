/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008

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
#include <structmember.h>
#include "librpc/rpc/pyrpc.h"
#include "lib/events/events.h"
#include "param/pyparam.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/pyrpc_util.h"
#include "auth/credentials/pycredentials.h"
#include "auth/gensec/gensec.h"

void initbase(void);

static PyTypeObject dcerpc_InterfaceType;

static PyTypeObject *ndr_syntax_id_Type;

static bool PyString_AsGUID(PyObject *object, struct GUID *uuid)
{
	NTSTATUS status;
	status = GUID_from_string(PyString_AsString(object), uuid);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return false;
	}
	return true;
}

static bool ndr_syntax_from_py_object(PyObject *object, struct ndr_syntax_id *syntax_id)
{
	ZERO_STRUCTP(syntax_id);

	if (PyString_Check(object)) {
		return PyString_AsGUID(object, &syntax_id->uuid);
	} else if (PyTuple_Check(object)) {
		if (PyTuple_Size(object) < 1 || PyTuple_Size(object) > 2) {
			PyErr_SetString(PyExc_ValueError, "Syntax ID tuple has invalid size");
			return false;
		}

		if (!PyString_Check(PyTuple_GetItem(object, 0))) {
			PyErr_SetString(PyExc_ValueError, "Expected GUID as first element in tuple");
			return false;
		}

		if (!PyString_AsGUID(PyTuple_GetItem(object, 0), &syntax_id->uuid)) 
			return false;

		if (!PyInt_Check(PyTuple_GetItem(object, 1))) {
			PyErr_SetString(PyExc_ValueError, "Expected version as second element in tuple");
			return false;
		}

		syntax_id->if_version = PyInt_AsLong(PyTuple_GetItem(object, 1));
		return true;
	}

	PyErr_SetString(PyExc_TypeError, "Expected UUID or syntax id tuple");
	return false;
}

static PyObject *py_iface_server_name(PyObject *obj, void *closure)
{
	const char *server_name;
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;

	server_name = dcerpc_server_name(iface->pipe);
	if (server_name == NULL)
		Py_RETURN_NONE;

	return PyString_FromString(server_name);
}

static PyObject *py_ndr_syntax_id(struct ndr_syntax_id *syntax_id)
{
	PyObject *ret;
	char *uuid_str;

	uuid_str = GUID_string(NULL, &syntax_id->uuid);
	if (uuid_str == NULL)
		return NULL;

	ret = Py_BuildValue("(s,i)", uuid_str, syntax_id->if_version);

	talloc_free(uuid_str);

	return ret;
}

static PyObject *py_iface_abstract_syntax(PyObject *obj, void *closure)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;

	return py_ndr_syntax_id(&iface->pipe->syntax);
}

static PyObject *py_iface_transfer_syntax(PyObject *obj, void *closure)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;

	return py_ndr_syntax_id(&iface->pipe->transfer_syntax);
}

static PyObject *py_iface_session_key(PyObject *obj, void *closure)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;
	DATA_BLOB session_key;

	NTSTATUS status = dcerpc_fetch_session_key(iface->pipe, &session_key);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	return PyString_FromStringAndSize((const char *)session_key.data, session_key.length);
}

static PyObject *py_iface_user_session_key(PyObject *obj, void *closure)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	struct gensec_security *security = NULL;
	DATA_BLOB session_key = data_blob_null;
	static PyObject *session_key_obj = NULL;

	if (iface->pipe == NULL) {
		PyErr_SetNTSTATUS(NT_STATUS_NO_USER_SESSION_KEY);
		return NULL;
	}

	if (iface->pipe->conn == NULL) {
		PyErr_SetNTSTATUS(NT_STATUS_NO_USER_SESSION_KEY);
		return NULL;
	}

	if (iface->pipe->conn->security_state.generic_state == NULL) {
		PyErr_SetNTSTATUS(NT_STATUS_NO_USER_SESSION_KEY);
		return NULL;
	}

	security = iface->pipe->conn->security_state.generic_state;

	mem_ctx = talloc_new(NULL);

	status = gensec_session_key(security, mem_ctx, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	session_key_obj = PyString_FromStringAndSize((const char *)session_key.data,
						     session_key.length);
	talloc_free(mem_ctx);
	return session_key_obj;
}

static PyObject *py_iface_get_timeout(PyObject *obj, void *closure)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;
	uint32_t timeout;

	timeout = dcerpc_binding_handle_set_timeout(iface->binding_handle, 0);
	dcerpc_binding_handle_set_timeout(iface->binding_handle, timeout);

	return PyLong_FromUnsignedLong(timeout);
}

static int py_iface_set_timeout(PyObject *obj, PyObject *value, void *closure)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;
	uint32_t timeout;

	timeout = PyLong_AsUnsignedLong(value);
	if (PyErr_Occurred() != NULL) {
		return -1;
	}

	dcerpc_binding_handle_set_timeout(iface->binding_handle, timeout);
	return 0;
}

static PyGetSetDef dcerpc_interface_getsetters[] = {
	{ discard_const_p(char, "server_name"), py_iface_server_name, NULL,
	  discard_const_p(char, "name of the server, if connected over SMB") },
	{ discard_const_p(char, "abstract_syntax"), py_iface_abstract_syntax, NULL, 
 	  discard_const_p(char, "syntax id of the abstract syntax") },
	{ discard_const_p(char, "transfer_syntax"), py_iface_transfer_syntax, NULL, 
 	  discard_const_p(char, "syntax id of the transfersyntax") },
	{ discard_const_p(char, "session_key"), py_iface_session_key, NULL,
	  discard_const_p(char, "session key (as used for blob encryption on LSA and SAMR)") },
	{ discard_const_p(char, "user_session_key"), py_iface_user_session_key, NULL,
	  discard_const_p(char, "user_session key (as used for blob encryption on DRSUAPI)") },
	{ discard_const_p(char, "request_timeout"), py_iface_get_timeout, py_iface_set_timeout,
	  discard_const_p(char, "request timeout, in seconds") },
	{ NULL }
};

static PyObject *py_iface_request(PyObject *self, PyObject *args, PyObject *kwargs)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)self;
	int opnum;
	DATA_BLOB data_in, data_out;
	NTSTATUS status;
	char *in_data;
	Py_ssize_t in_length;
	PyObject *ret;
	PyObject *object = NULL;
	struct GUID object_guid;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	uint32_t out_flags = 0;
	const char *kwnames[] = { "opnum", "data", "object", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "is#|O:request", 
		discard_const_p(char *, kwnames), &opnum, &in_data, &in_length, &object)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	data_in.data = (uint8_t *)talloc_memdup(mem_ctx, in_data, in_length);
	data_in.length = in_length;

	ZERO_STRUCT(data_out);

	if (object != NULL && !PyString_AsGUID(object, &object_guid)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	status = dcerpc_binding_handle_raw_call(iface->binding_handle,
						object?&object_guid:NULL,
						opnum,
						0, /* in_flags */
						data_in.data,
						data_in.length,
						mem_ctx,
						&data_out.data,
						&data_out.length,
						&out_flags);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetDCERPCStatus(iface->pipe, status);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = PyString_FromStringAndSize((char *)data_out.data, data_out.length);

	talloc_free(mem_ctx);
	return ret;
}

static PyMethodDef dcerpc_interface_methods[] = {
	{ "request", (PyCFunction)py_iface_request, METH_VARARGS|METH_KEYWORDS, "S.request(opnum, data, object=None) -> data\nMake a raw request" },
	{ NULL, NULL, 0, NULL },
};

static void dcerpc_interface_dealloc(PyObject* self)
{
	dcerpc_InterfaceObject *interface = (dcerpc_InterfaceObject *)self;
	interface->binding_handle = NULL;
	interface->pipe = NULL;
	TALLOC_FREE(interface->mem_ctx);
	self->ob_type->tp_free(self);
}

static PyObject *dcerpc_interface_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *ret;
	const char *binding_string = NULL;
	PyObject *py_lp_ctx = Py_None;
	PyObject *py_credentials = Py_None;
	PyObject *syntax = Py_None;
	PyObject *py_basis = Py_None;
	const char *kwnames[] = {
		"binding", "syntax", "lp_ctx", "credentials", "basis_connection", NULL
	};
	static struct ndr_interface_table dummy_table;
	PyObject *args2 = Py_None;
	PyObject *kwargs2 = Py_None;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sO|OOO:connect", discard_const_p(char *, kwnames), &binding_string, &syntax, &py_lp_ctx, &py_credentials, &py_basis)) {
		return NULL;
	}

	if (strncmp(binding_string, "irpc:", 5) == 0) {
		PyErr_SetString(PyExc_ValueError, "irpc: transport not supported");
		return NULL;
	}

	/*
	 * Fill a dummy interface table struct. TODO: In the future, we should
	 * rather just allow connecting without requiring an interface table.
	 *
	 * We just fill the syntax during the connect, but keep the memory valid
	 * the whole time.
	 */
	if (!ndr_syntax_from_py_object(syntax, &dummy_table.syntax_id)) {
		return NULL;
	}

	args2 = Py_BuildValue("(s)", binding_string);
	if (args2 == NULL) {
		return NULL;
	}

	kwargs2 = Py_BuildValue("{s:O,s:O,s:O}",
				"lp_ctx", py_lp_ctx,
				"credentials", py_credentials,
				"basis_connection", py_basis);
	if (kwargs2 == NULL) {
		Py_DECREF(args2);
		return NULL;
	}

	ret = py_dcerpc_interface_init_helper(type, args2, kwargs2, &dummy_table);
	ZERO_STRUCT(dummy_table.syntax_id);
	Py_DECREF(args2);
	Py_DECREF(kwargs2);
	return ret;
}

static PyTypeObject dcerpc_InterfaceType = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "dcerpc.ClientConnection",
	.tp_basicsize = sizeof(dcerpc_InterfaceObject),
	.tp_dealloc = dcerpc_interface_dealloc,
	.tp_getset = dcerpc_interface_getsetters,
	.tp_methods = dcerpc_interface_methods,
	.tp_doc = "ClientConnection(binding, syntax, lp_ctx=None, credentials=None) -> connection\n"
"\n"
"binding should be a DCE/RPC binding string (for example: ncacn_ip_tcp:127.0.0.1)\n"
"syntax should be a tuple with a GUID and version number of an interface\n"
"lp_ctx should be a path to a smb.conf file or a param.LoadParm object\n"
"credentials should be a credentials.Credentials object.\n\n",
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = dcerpc_interface_new,
};

static PyObject *py_transfer_syntax_ndr_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return py_dcerpc_syntax_init_helper(type, args, kwargs, &ndr_transfer_syntax_ndr);
}

static PyTypeObject py_transfer_syntax_ndr_SyntaxType = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "base.transfer_syntax_ndr",
	.tp_doc = "transfer_syntax_ndr()\n",
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_transfer_syntax_ndr_new,
};

static PyObject *py_transfer_syntax_ndr64_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return py_dcerpc_syntax_init_helper(type, args, kwargs, &ndr_transfer_syntax_ndr64);
}

static PyTypeObject py_transfer_syntax_ndr64_SyntaxType = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "base.transfer_syntax_ndr64",
	.tp_doc = "transfer_syntax_ndr64()\n",
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_transfer_syntax_ndr64_new,
};

static PyObject *py_bind_time_features_syntax_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = {
		"features", NULL
	};
	unsigned long long features = 0;
	struct ndr_syntax_id syntax;
	PyObject *args2 = Py_None;
	PyObject *kwargs2 = Py_None;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "K:features", discard_const_p(char *, kwnames), &features)) {
		return NULL;
	}

	args2 = Py_BuildValue("()");
	if (args2 == NULL) {
		return NULL;
	}

	kwargs2 = Py_BuildValue("{}");
	if (kwargs2 == NULL) {
		Py_DECREF(args2);
		return NULL;
	}

	syntax = dcerpc_construct_bind_time_features(features);

	return py_dcerpc_syntax_init_helper(type, args2, kwargs2, &syntax);
}

static PyTypeObject py_bind_time_features_syntax_SyntaxType = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "base.bind_time_features_syntax",
	.tp_doc = "bind_time_features_syntax(features)\n",
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_bind_time_features_syntax_new,
};

void initbase(void)
{
	PyObject *m;
	PyObject *dep_samba_dcerpc_misc;

	dep_samba_dcerpc_misc = PyImport_ImportModule("samba.dcerpc.misc");
	if (dep_samba_dcerpc_misc == NULL)
		return;

	ndr_syntax_id_Type = (PyTypeObject *)PyObject_GetAttrString(dep_samba_dcerpc_misc, "ndr_syntax_id");
	if (ndr_syntax_id_Type == NULL)
		return;

	py_transfer_syntax_ndr_SyntaxType.tp_base = ndr_syntax_id_Type;
	py_transfer_syntax_ndr_SyntaxType.tp_basicsize = pytalloc_BaseObject_size();
	py_transfer_syntax_ndr64_SyntaxType.tp_base = ndr_syntax_id_Type;
	py_transfer_syntax_ndr64_SyntaxType.tp_basicsize = pytalloc_BaseObject_size();
	py_bind_time_features_syntax_SyntaxType.tp_base = ndr_syntax_id_Type;
	py_bind_time_features_syntax_SyntaxType.tp_basicsize = pytalloc_BaseObject_size();

	if (PyType_Ready(&dcerpc_InterfaceType) < 0)
		return;

	if (PyType_Ready(&py_transfer_syntax_ndr_SyntaxType) < 0)
		return;
	if (PyType_Ready(&py_transfer_syntax_ndr64_SyntaxType) < 0)
		return;
	if (PyType_Ready(&py_bind_time_features_syntax_SyntaxType) < 0)
		return;

	m = Py_InitModule3("base", NULL, "DCE/RPC protocol implementation");
	if (m == NULL)
		return;

	Py_INCREF((PyObject *)&dcerpc_InterfaceType);
	PyModule_AddObject(m, "ClientConnection", (PyObject *)&dcerpc_InterfaceType);

	Py_INCREF((PyObject *)(void *)&py_transfer_syntax_ndr_SyntaxType);
	PyModule_AddObject(m, "transfer_syntax_ndr", (PyObject *)(void *)&py_transfer_syntax_ndr_SyntaxType);
	Py_INCREF((PyObject *)(void *)&py_transfer_syntax_ndr64_SyntaxType);
	PyModule_AddObject(m, "transfer_syntax_ndr64", (PyObject *)(void *)&py_transfer_syntax_ndr64_SyntaxType);
	Py_INCREF((PyObject *)(void *)&py_bind_time_features_syntax_SyntaxType);
	PyModule_AddObject(m, "bind_time_features_syntax", (PyObject *)(void *)&py_bind_time_features_syntax_SyntaxType);
}
