/*
   Unix SMB/CIFS implementation.

   Python interface to ldb - utility functions.

   Copyright (C) 2007-2010 Jelmer Vernooij <jelmer@samba.org>

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

#include <Python.h>
#include "ldb.h"
#include "pyldb.h"

static PyObject *ldb_module = NULL;

#if PY_MAJOR_VERSION >= 3
#define PyStr_Check PyUnicode_Check
#define PyStr_AsUTF8 PyUnicode_AsUTF8
#else
#define PyStr_Check PyString_Check
#define PyStr_AsUTF8 PyString_AsString
#endif

/**
 * Find out PyTypeObject in ldb module for a given typename
 */
static PyTypeObject * PyLdb_GetPyType(const char *typename)
{
	PyObject *py_obj = NULL;

	if (ldb_module == NULL) {
		ldb_module = PyImport_ImportModule("ldb");
		if (ldb_module == NULL) {
			return NULL;
		}
	}

	py_obj = PyObject_GetAttrString(ldb_module, typename);

	return (PyTypeObject*)py_obj;
}

/**
 * Obtain a ldb DN from a Python object.
 *
 * @param mem_ctx Memory context
 * @param object Python object
 * @param ldb_ctx LDB context
 * @return Whether or not the conversion succeeded
 */
bool pyldb_Object_AsDn(TALLOC_CTX *mem_ctx, PyObject *object, 
		   struct ldb_context *ldb_ctx, struct ldb_dn **dn)
{
	struct ldb_dn *odn;
	PyTypeObject *PyLdb_Dn_Type;

	if (ldb_ctx != NULL && PyStr_Check(object)) {
		odn = ldb_dn_new(mem_ctx, ldb_ctx, PyStr_AsUTF8(object));
		*dn = odn;
		return true;
	}

	if (ldb_ctx != NULL && PyBytes_Check(object)) {
		odn = ldb_dn_new(mem_ctx, ldb_ctx, PyBytes_AsString(object));
		*dn = odn;
		return true;
	}

	PyLdb_Dn_Type = PyLdb_GetPyType("Dn");
	if (PyLdb_Dn_Type == NULL) {
		return false;
	}

	if (PyObject_TypeCheck(object, PyLdb_Dn_Type)) {
		*dn = pyldb_Dn_AsDn(object);
		return true;
	}

	PyErr_SetString(PyExc_TypeError, "Expected DN");
	return false;
}

PyObject *pyldb_Dn_FromDn(struct ldb_dn *dn)
{
	PyLdbDnObject *py_ret;
	PyTypeObject *PyLdb_Dn_Type;

	if (dn == NULL) {
		Py_RETURN_NONE;
	}

	PyLdb_Dn_Type = PyLdb_GetPyType("Dn");
	if (PyLdb_Dn_Type == NULL) {
		return NULL;
	}

	py_ret = (PyLdbDnObject *)PyLdb_Dn_Type->tp_alloc(PyLdb_Dn_Type, 0);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = talloc_new(NULL);
	py_ret->dn = talloc_reference(py_ret->mem_ctx, dn);
	return (PyObject *)py_ret;
}
