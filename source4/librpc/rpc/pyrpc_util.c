/*
   Unix SMB/CIFS implementation.

   Python interface to DCE/RPC library - utility functions.

   Copyright (C) 2010 Jelmer Vernooij <jelmer@samba.org>
   Copyright (C) 2010 Andrew Tridgell <tridge@samba.org>

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
#include "librpc/rpc/pyrpc_util.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/pyrpc.h"
#include "param/pyparam.h"
#include "auth/credentials/pycredentials.h"
#include "lib/events/events.h"
#include "lib/messaging/messaging.h"
#include "lib/messaging/irpc.h"

bool py_check_dcerpc_type(PyObject *obj, const char *module, const char *type_name)
{
	PyObject *mod;
	PyTypeObject *type;
	bool ret;

	mod = PyImport_ImportModule(module);

	if (mod == NULL) {
		PyErr_Format(PyExc_RuntimeError, "Unable to import %s to check type %s",
			module, type_name);
		return false;
	}

	type = (PyTypeObject *)PyObject_GetAttrString(mod, type_name);
	Py_DECREF(mod);
	if (type == NULL) {
		PyErr_Format(PyExc_RuntimeError, "Unable to find type %s in module %s",
			module, type_name);
		return false;
	}

	ret = PyObject_TypeCheck(obj, type);
	Py_DECREF(type);

	if (!ret)
		PyErr_Format(PyExc_TypeError, "Expected type %s.%s, got %s",
			module, type_name, Py_TYPE(obj)->tp_name);

	return ret;
}

/*
  connect to a IRPC pipe from python
 */
static NTSTATUS pyrpc_irpc_connect(TALLOC_CTX *mem_ctx, const char *irpc_server,
				   const struct ndr_interface_table *table,
				   struct tevent_context *event_ctx,
				   struct loadparm_context *lp_ctx,
				   struct dcerpc_binding_handle **binding_handle)
{
	struct imessaging_context *msg;

	msg = imessaging_client_init(mem_ctx, lp_ctx, event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	*binding_handle = irpc_binding_handle_by_name(mem_ctx, msg, irpc_server, table);
	if (*binding_handle == NULL) {
		talloc_free(msg);
		return NT_STATUS_INVALID_PIPE_STATE;
	}

	/*
	 * Note: this allows nested event loops to happen,
	 * but as there's no top level event loop it's not that critical.
	 */
	dcerpc_binding_handle_set_sync_ev(*binding_handle, event_ctx);

	return NT_STATUS_OK;
}

PyObject *py_dcerpc_interface_init_helper(PyTypeObject *type, PyObject *args, PyObject *kwargs,
					  const struct ndr_interface_table *table)
{
	dcerpc_InterfaceObject *ret;
	const char *binding_string;
	PyObject *py_lp_ctx = Py_None, *py_credentials = Py_None, *py_basis = Py_None;
	NTSTATUS status;
	unsigned int timeout = (unsigned int)-1;
	const char *kwnames[] = {
		"binding", "lp_ctx", "credentials", "timeout", "basis_connection", NULL
	};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|OOIO:samr", discard_const_p(char *, kwnames), &binding_string, &py_lp_ctx, &py_credentials, &timeout, &py_basis)) {
		return NULL;
	}

	status = dcerpc_init();
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	ret = PyObject_New(dcerpc_InterfaceObject, type);
	ret->pipe = NULL;
	ret->binding_handle = NULL;
	ret->mem_ctx = talloc_new(NULL);
	if (ret->mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (strncmp(binding_string, "irpc:", 5) == 0) {
		struct tevent_context *event_ctx;
		struct loadparm_context *lp_ctx;

		event_ctx = s4_event_context_init(ret->mem_ctx);
		if (event_ctx == NULL) {
			PyErr_SetString(PyExc_TypeError, "Expected loadparm context");
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		lp_ctx = lpcfg_from_py_object(event_ctx, py_lp_ctx);
		if (lp_ctx == NULL) {
			PyErr_SetString(PyExc_TypeError, "Expected loadparm context");
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		status = pyrpc_irpc_connect(ret->mem_ctx, binding_string+5, table,
					    event_ctx, lp_ctx, &ret->binding_handle);
		if (!NT_STATUS_IS_OK(status)) {
			PyErr_SetNTSTATUS(status);
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}
	} else if (py_basis != Py_None) {
		struct dcerpc_pipe *base_pipe;
		PyObject *py_base;
		PyTypeObject *ClientConnection_Type;

		py_base = PyImport_ImportModule("samba.dcerpc.base");
		if (py_base == NULL) {
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		ClientConnection_Type = (PyTypeObject *)PyObject_GetAttrString(py_base, "ClientConnection");
		if (ClientConnection_Type == NULL) {
			PyErr_SetNone(PyExc_TypeError);
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		if (!PyObject_TypeCheck(py_basis, ClientConnection_Type)) {
			PyErr_SetString(PyExc_TypeError, "basis_connection must be a DCE/RPC connection");
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		base_pipe = talloc_reference(ret->mem_ctx,
					 ((dcerpc_InterfaceObject *)py_basis)->pipe);
		if (base_pipe == NULL) {
			PyErr_NoMemory();
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		status = dcerpc_secondary_context(base_pipe, &ret->pipe, table);
		if (!NT_STATUS_IS_OK(status)) {
			PyErr_SetNTSTATUS(status);
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		ret->pipe = talloc_steal(ret->mem_ctx, ret->pipe);
	} else {
		struct tevent_context *event_ctx;
		struct loadparm_context *lp_ctx;
		struct cli_credentials *credentials;

		event_ctx = s4_event_context_init(ret->mem_ctx);
		if (event_ctx == NULL) {
			PyErr_SetString(PyExc_TypeError, "Expected loadparm context");
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		lp_ctx = lpcfg_from_py_object(event_ctx, py_lp_ctx);
		if (lp_ctx == NULL) {
			PyErr_SetString(PyExc_TypeError, "Expected loadparm context");
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		credentials = cli_credentials_from_py_object(py_credentials);
		if (credentials == NULL) {
			PyErr_SetString(PyExc_TypeError, "Expected credentials");
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}
		status = dcerpc_pipe_connect(ret->mem_ctx, &ret->pipe, binding_string,
			     table, credentials, event_ctx, lp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			PyErr_SetNTSTATUS(status);
			TALLOC_FREE(ret->mem_ctx);
			return NULL;
		}

		/*
		 * the event context is cached under the connection,
		 * so let it be a child of it.
		 */
		talloc_steal(ret->pipe->conn, event_ctx);
	}

	if (ret->pipe) {
		ret->pipe->conn->flags |= DCERPC_NDR_REF_ALLOC;
		ret->binding_handle = ret->pipe->binding_handle;
	}

	/* reset timeout for the handle */
	if ((timeout != ((unsigned int)-1)) && (ret->binding_handle != NULL)) {
		dcerpc_binding_handle_set_timeout(ret->binding_handle, timeout);
	}

	return (PyObject *)ret;
}

static PyObject *py_dcerpc_run_function(dcerpc_InterfaceObject *iface,
					const struct PyNdrRpcMethodDef *md,
					PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	void *r;
	PyObject *result = Py_None;

	if (md->pack_in_data == NULL || md->unpack_out_data == NULL) {
		PyErr_SetString(PyExc_NotImplementedError, "No marshalling code available yet");
		return NULL;
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	r = talloc_zero_size(mem_ctx, md->table->calls[md->opnum].struct_size);
	if (r == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!md->pack_in_data(args, kwargs, r)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	status = md->call(iface->binding_handle, mem_ctx, r);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetDCERPCStatus(iface->pipe, status);
		talloc_free(mem_ctx);
		return NULL;
	}

	result = md->unpack_out_data(r);

	talloc_free(mem_ctx);
	return result;
}

static PyObject *py_dcerpc_call_wrapper(PyObject *self, PyObject *args, void *wrapped, PyObject *kwargs)
{	
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)self;
	const struct PyNdrRpcMethodDef *md = (const struct PyNdrRpcMethodDef *)wrapped;

	return py_dcerpc_run_function(iface, md, args, kwargs);
}

bool PyInterface_AddNdrRpcMethods(PyTypeObject *ifacetype, const struct PyNdrRpcMethodDef *mds)
{
	int i;
	for (i = 0; mds[i].name; i++) {
		PyObject *ret;
		struct wrapperbase *wb = (struct wrapperbase *)calloc(sizeof(struct wrapperbase), 1);

		if (wb == NULL) {
			return false;
		}
		wb->name = discard_const_p(char, mds[i].name);
		wb->flags = PyWrapperFlag_KEYWORDS;
		wb->wrapper = (wrapperfunc)py_dcerpc_call_wrapper;
		wb->doc = discard_const_p(char, mds[i].doc);

		ret = PyDescr_NewWrapper(ifacetype, wb, discard_const_p(void, &mds[i]));

		PyDict_SetItemString(ifacetype->tp_dict, mds[i].name, 
				     (PyObject *)ret);
	}

	return true;
}

PyObject *py_dcerpc_syntax_init_helper(PyTypeObject *type, PyObject *args, PyObject *kwargs,
				       const struct ndr_syntax_id *syntax)
{
	PyObject *ret;
	struct ndr_syntax_id *obj;
	const char *kwnames[] = { NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, ":abstract_syntax", discard_const_p(char *, kwnames))) {
		return NULL;
	}

	ret = pytalloc_new(struct ndr_syntax_id, type);
	if (ret == NULL) {
		return NULL;
	}

	obj = (struct ndr_syntax_id *)pytalloc_get_ptr(ret);
	*obj = *syntax;

	return ret;
}

void PyErr_SetDCERPCStatus(struct dcerpc_pipe *p, NTSTATUS status)
{
	if (p && NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		status = dcerpc_fault_to_nt_status(p->last_fault_code);
	}
	PyErr_SetNTSTATUS(status);
}


/*
  take a NDR structure that has a type in a python module and return
  it as a python object

  r is the NDR structure pointer (a C structure)

  r_ctx is the context that is a parent of r. It will be referenced by
  the resulting python object

  This MUST only be used by objects that are based on pytalloc_Object
  otherwise the pytalloc_reference_ex() will fail.
 */
PyObject *py_return_ndr_struct(const char *module_name, const char *type_name,
			       TALLOC_CTX *r_ctx, void *r)
{
	PyTypeObject *py_type;
	PyObject *module;

	if (r == NULL) {
		Py_RETURN_NONE;
	}

	module = PyImport_ImportModule(module_name);
	if (module == NULL) {
		return NULL;
	}

	py_type = (PyTypeObject *)PyObject_GetAttrString(module, type_name);
	if (py_type == NULL) {
		return NULL;
	}

	return pytalloc_reference_ex(py_type, r_ctx, r);
}

PyObject *PyString_FromStringOrNULL(const char *str)
{
	if (str == NULL) {
		Py_RETURN_NONE;
	}
	return PyString_FromString(str);
}
