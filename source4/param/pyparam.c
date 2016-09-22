/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
   
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
#include "param/param.h"
#include "param/loadparm.h"
#include <pytalloc.h>
#include "dynconfig/dynconfig.h"

void initparam(void);

#define PyLoadparmContext_AsLoadparmContext(obj) pytalloc_get_type(obj, struct loadparm_context)
#define PyLoadparmService_AsLoadparmService(obj) pytalloc_get_type(obj, struct loadparm_service)

extern PyTypeObject PyLoadparmContext;
extern PyTypeObject PyLoadparmService;

static PyObject *PyLoadparmService_FromService(struct loadparm_service *service)
{
	return pytalloc_reference(&PyLoadparmService, service);
}

static PyObject *py_lp_ctx_get_helper(struct loadparm_context *lp_ctx, const char *service_name, const char *param_name)
{
	struct parm_struct *parm = NULL;
	void *parm_ptr = NULL;
	int i;

	if (service_name != NULL && strwicmp(service_name, GLOBAL_NAME) && 
		strwicmp(service_name, GLOBAL_NAME2)) {
		struct loadparm_service *service;
		/* its a share parameter */
		service = lpcfg_service(lp_ctx, service_name);
		if (service == NULL) {
			return NULL;
		}
		if (strchr(param_name, ':')) {
			/* its a parametric option on a share */
			const char *type = talloc_strndup(lp_ctx, param_name,
											  strcspn(param_name, ":"));
			const char *option = strchr(param_name, ':') + 1;
			const char *value;
			if (type == NULL || option == NULL) {
			return NULL;
			}
			value = lpcfg_get_parametric(lp_ctx, service, type, option);
			if (value == NULL) {
			return NULL;
			}
			return PyString_FromString(value);
		}

		parm = lpcfg_parm_struct(lp_ctx, param_name);
		if (parm == NULL || parm->p_class == P_GLOBAL) {
			return NULL;
		}
		parm_ptr = lpcfg_parm_ptr(lp_ctx, service, parm);
    } else if (strchr(param_name, ':')) {
		/* its a global parametric option */
		const char *type = talloc_strndup(lp_ctx,
				  param_name, strcspn(param_name, ":"));
		const char *option = strchr(param_name, ':') + 1;
		const char *value;
		if (type == NULL || option == NULL) {
			return NULL;
		}
		value = lpcfg_get_parametric(lp_ctx, NULL, type, option);
		if (value == NULL)
			return NULL;
		return PyString_FromString(value);
	} else {
		/* its a global parameter */
		parm = lpcfg_parm_struct(lp_ctx, param_name);
		if (parm == NULL) {
			return NULL;
		}
		parm_ptr = lpcfg_parm_ptr(lp_ctx, NULL, parm);
	}

	if (parm == NULL || parm_ptr == NULL) {
		return NULL;
    }

    /* construct and return the right type of python object */
    switch (parm->type) {
    case P_CHAR:
	return PyString_FromFormat("%c", *(char *)parm_ptr);
    case P_STRING:
    case P_USTRING:
	return PyString_FromString(*(char **)parm_ptr);
    case P_BOOL:
	return PyBool_FromLong(*(bool *)parm_ptr);
    case P_BOOLREV:
	return PyBool_FromLong(!(*(bool *)parm_ptr));
    case P_INTEGER:
    case P_OCTAL:
    case P_BYTES:
	return PyLong_FromLong(*(int *)parm_ptr);
    case P_ENUM:
	for (i=0; parm->enum_list[i].name; i++) {
	    if (*(int *)parm_ptr == parm->enum_list[i].value) {
		return PyString_FromString(parm->enum_list[i].name);
	    }
	}
	return NULL;
    case P_CMDLIST:
    case P_LIST: 
	{
	    int j;
	    const char **strlist = *(const char ***)parm_ptr;
	    PyObject *pylist;
		
	    if(strlist == NULL) {
		    return PyList_New(0);
	    }
		
	    pylist = PyList_New(str_list_length(strlist));
	    for (j = 0; strlist[j]; j++) 
		PyList_SetItem(pylist, j, 
			       PyString_FromString(strlist[j]));
	    return pylist;
	}
    }
    return NULL;

}

static PyObject *py_lp_ctx_load(PyObject *self, PyObject *args)
{
	char *filename;
	bool ret;
	if (!PyArg_ParseTuple(args, "s", &filename))
		return NULL;

	ret = lpcfg_load(PyLoadparmContext_AsLoadparmContext(self), filename);

	if (!ret) {
		PyErr_Format(PyExc_RuntimeError, "Unable to load file %s", filename);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_lp_ctx_load_default(PyObject *self, PyObject *unused)
{
	bool ret;
        ret = lpcfg_load_default(PyLoadparmContext_AsLoadparmContext(self));

	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "Unable to load default file");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_lp_ctx_get(PyObject *self, PyObject *args)
{
	char *param_name;
	char *section_name = NULL;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "s|z", &param_name, &section_name))
		return NULL;

	ret = py_lp_ctx_get_helper(PyLoadparmContext_AsLoadparmContext(self), section_name, param_name);
	if (ret == NULL)
		Py_RETURN_NONE;
	return ret;
}

static PyObject *py_lp_ctx_is_myname(PyObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	return PyBool_FromLong(lpcfg_is_myname(PyLoadparmContext_AsLoadparmContext(self), name));
}

static PyObject *py_lp_ctx_is_mydomain(PyObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	return PyBool_FromLong(lpcfg_is_mydomain(PyLoadparmContext_AsLoadparmContext(self), name));
}

static PyObject *py_lp_ctx_set(PyObject *self, PyObject *args)
{
	char *name, *value;
	bool ret;
	if (!PyArg_ParseTuple(args, "ss", &name, &value))
		return NULL;

	ret = lpcfg_set_cmdline(PyLoadparmContext_AsLoadparmContext(self), name, value);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "Unable to set parameter");
		return NULL;
        }

	Py_RETURN_NONE;
}

static PyObject *py_lp_ctx_private_path(PyObject *self, PyObject *args)
{
	char *name, *path;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	path = lpcfg_private_path(NULL, PyLoadparmContext_AsLoadparmContext(self), name);
	ret = PyString_FromString(path);
	talloc_free(path);

	return ret;
}

static PyObject *py_lp_ctx_services(PyObject *self, PyObject *unused)
{
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	PyObject *ret;
	int i;
	ret = PyList_New(lpcfg_numservices(lp_ctx));
	for (i = 0; i < lpcfg_numservices(lp_ctx); i++) {
		struct loadparm_service *service = lpcfg_servicebynum(lp_ctx, i);
		if (service != NULL) {
			PyList_SetItem(ret, i, PyString_FromString(lpcfg_servicename(service)));
		}
	}
	return ret;
}

static PyObject *py_lp_ctx_server_role(PyObject *self, PyObject *unused)
{
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	uint32_t role;
	const char *role_str;

	role = lpcfg_server_role(lp_ctx);
	role_str = server_role_str(role);

	return PyString_FromString(role_str);
}

static PyObject *py_lp_dump(PyObject *self, PyObject *args)
{
	PyObject *py_stream;
	bool show_defaults = false;
	FILE *f;
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);

	if (!PyArg_ParseTuple(args, "O|b", &py_stream, &show_defaults))
		return NULL;

	f = PyFile_AsFile(py_stream);
	if (f == NULL) {
		return NULL;
	}

	lpcfg_dump(lp_ctx, f, show_defaults, lpcfg_numservices(lp_ctx));

	Py_RETURN_NONE;
}

static PyObject *py_lp_dump_a_parameter(PyObject *self, PyObject *args)
{
	PyObject *py_stream;
	char *param_name;
	const char *section_name = NULL;
	FILE *f;
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	struct loadparm_service *service;
	bool ret;

	if (!PyArg_ParseTuple(args, "Os|z", &py_stream, &param_name, &section_name))
		return NULL;

	f = PyFile_AsFile(py_stream);
	if (f == NULL) {
		return NULL;
	}

	if (section_name != NULL && strwicmp(section_name, GLOBAL_NAME) &&
		strwicmp(section_name, GLOBAL_NAME2)) {
		/* it's a share parameter */
		service = lpcfg_service(lp_ctx, section_name);
		if (service == NULL) {
			PyErr_Format(PyExc_RuntimeError, "Unknown section %s", section_name);
			return NULL;
		}
	} else {
		/* it's global */
		service = NULL;
		section_name = "global";
	}

	ret = lpcfg_dump_a_parameter(lp_ctx, service, param_name, f);

	if (!ret) {
		PyErr_Format(PyExc_RuntimeError, "Parameter %s unknown for section %s", param_name, section_name);
		return NULL;
	}

	Py_RETURN_NONE;

}

static PyObject *py_lp_log_level(PyObject *self, PyObject *unused)
{
	int ret = DEBUGLEVEL_CLASS[DBGC_CLASS];
	return PyInt_FromLong(ret);
}


static PyObject *py_samdb_url(PyObject *self, PyObject *unused)
{
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	return PyString_FromFormat("tdb://%s/sam.ldb", lpcfg_private_dir(lp_ctx));
}


static PyMethodDef py_lp_ctx_methods[] = {
	{ "load", py_lp_ctx_load, METH_VARARGS,
		"S.load(filename) -> None\n"
		"Load specified file." },
	{ "load_default", py_lp_ctx_load_default, METH_NOARGS,
        	"S.load_default() -> None\n"
		"Load default smb.conf file." },
	{ "is_myname", py_lp_ctx_is_myname, METH_VARARGS,
		"S.is_myname(name) -> bool\n"
		"Check whether the specified name matches one of our netbios names." },
	{ "is_mydomain", py_lp_ctx_is_mydomain, METH_VARARGS,
		"S.is_mydomain(name) -> bool\n"
		"Check whether the specified name matches our domain name." },
	{ "get", py_lp_ctx_get, METH_VARARGS,
        	"S.get(name, service_name) -> value\n"
		"Find specified parameter." },
	{ "set", py_lp_ctx_set, METH_VARARGS,
		"S.set(name, value) -> bool\n"
		"Change a parameter." },
	{ "private_path", py_lp_ctx_private_path, METH_VARARGS,
		"S.private_path(name) -> path\n" },
	{ "services", py_lp_ctx_services, METH_NOARGS,
		"S.services() -> list" },
	{ "server_role", py_lp_ctx_server_role, METH_NOARGS,
		"S.server_role() -> value\n"
		"Get the server role." },
	{ "dump", py_lp_dump, METH_VARARGS,
		"S.dump(stream, show_defaults=False)" },
	{ "log_level", py_lp_log_level, METH_NOARGS,
		"S.log_level() -> int\n Get the active log level" },
	{ "dump_a_parameter", py_lp_dump_a_parameter, METH_VARARGS,
		"S.dump_a_parameter(stream, name, service_name)" },
	{ "samdb_url", py_samdb_url, METH_NOARGS,
	        "S.samdb_url() -> string\n"
	        "Returns the current URL for sam.ldb." },
	{ NULL }
};

static PyObject *py_lp_ctx_default_service(PyObject *self, void *closure)
{
	return PyLoadparmService_FromService(lpcfg_default_service(PyLoadparmContext_AsLoadparmContext(self)));
}

static PyObject *py_lp_ctx_config_file(PyObject *self, void *closure)
{
	const char *configfile = lpcfg_configfile(PyLoadparmContext_AsLoadparmContext(self));
	if (configfile == NULL)
		Py_RETURN_NONE;
	else
		return PyString_FromString(configfile);
}

static PyGetSetDef py_lp_ctx_getset[] = {
	{ discard_const_p(char, "default_service"), (getter)py_lp_ctx_default_service, NULL, NULL },
	{ discard_const_p(char, "configfile"), (getter)py_lp_ctx_config_file, NULL,
	  discard_const_p(char, "Name of last config file that was loaded.") },
	{ NULL }
};

static PyObject *py_lp_ctx_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return pytalloc_reference(type, loadparm_init_global(false));
}

static Py_ssize_t py_lp_ctx_len(PyObject *self)
{
	return lpcfg_numservices(PyLoadparmContext_AsLoadparmContext(self));
}

static PyObject *py_lp_ctx_getitem(PyObject *self, PyObject *name)
{
	struct loadparm_service *service;
	if (!PyString_Check(name)) {
		PyErr_SetString(PyExc_TypeError, "Only string subscripts are supported");
		return NULL;
	}
	service = lpcfg_service(PyLoadparmContext_AsLoadparmContext(self), PyString_AsString(name));
	if (service == NULL) {
		PyErr_SetString(PyExc_KeyError, "No such section");
		return NULL;
	}
	return PyLoadparmService_FromService(service);
}

static PyMappingMethods py_lp_ctx_mapping = {
	.mp_length = (lenfunc)py_lp_ctx_len,
	.mp_subscript = (binaryfunc)py_lp_ctx_getitem,
};

PyTypeObject PyLoadparmContext = {
	.tp_name = "param.LoadParm",
	.tp_getset = py_lp_ctx_getset,
	.tp_methods = py_lp_ctx_methods,
	.tp_new = py_lp_ctx_new,
	.tp_as_mapping = &py_lp_ctx_mapping,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject *py_lp_service_dump(PyObject *self, PyObject *args)
{
	PyObject *py_stream;
	bool show_defaults = false;
	FILE *f;
	struct loadparm_service *service = PyLoadparmService_AsLoadparmService(self);
	struct loadparm_service *default_service;
	PyObject *py_default_service;

	if (!PyArg_ParseTuple(args, "OO|b", &py_stream, &py_default_service,
						  &show_defaults))
		return NULL;

	f = PyFile_AsFile(py_stream);
	if (f == NULL) {
		return NULL;
	}

	if (!PyObject_TypeCheck(py_default_service, &PyLoadparmService)) {
		PyErr_SetNone(PyExc_TypeError);
		return NULL;
	}

	default_service = PyLoadparmService_AsLoadparmService(py_default_service);

	lpcfg_dump_one(f, show_defaults, service, default_service);

	Py_RETURN_NONE;
}

static PyMethodDef py_lp_service_methods[] = {
	{ "dump", (PyCFunction)py_lp_service_dump, METH_VARARGS, 
		"S.dump(f, default_service, show_defaults=False)" },
	{ NULL }
};

PyTypeObject PyLoadparmService = {
	.tp_name = "param.LoadparmService",
	.tp_methods = py_lp_service_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject *py_default_path(PyObject *self)
{
	return PyString_FromString(lp_default_path());
}

static PyObject *py_setup_dir(PyObject *self)
{
	return PyString_FromString(dyn_SETUPDIR);
}

static PyObject *py_modules_dir(PyObject *self)
{
	return PyString_FromString(dyn_MODULESDIR);
}

static PyObject *py_bin_dir(PyObject *self)
{
	return PyString_FromString(dyn_BINDIR);
}

static PyObject *py_sbin_dir(PyObject *self)
{
	return PyString_FromString(dyn_SBINDIR);
}

static PyMethodDef pyparam_methods[] = {
	{ "default_path", (PyCFunction)py_default_path, METH_NOARGS, 
		"Returns the default smb.conf path." },
	{ "setup_dir", (PyCFunction)py_setup_dir, METH_NOARGS,
		"Returns the compiled in location of provision tempates." },
	{ "modules_dir", (PyCFunction)py_modules_dir, METH_NOARGS,
		"Returns the compiled in location of modules." },
	{ "bin_dir", (PyCFunction)py_bin_dir, METH_NOARGS,
		"Returns the compiled in BINDIR." },
	{ "sbin_dir", (PyCFunction)py_sbin_dir, METH_NOARGS,
		"Returns the compiled in SBINDIR." },
	{ NULL }
};

void initparam(void)
{
	PyObject *m;

	if (pytalloc_BaseObject_PyType_Ready(&PyLoadparmContext) < 0)
		return;

	if (pytalloc_BaseObject_PyType_Ready(&PyLoadparmService) < 0)
		return;

	m = Py_InitModule3("param", pyparam_methods, "Parsing and writing Samba configuration files.");
	if (m == NULL)
		return;

	Py_INCREF(&PyLoadparmContext);
	PyModule_AddObject(m, "LoadParm", (PyObject *)&PyLoadparmContext);
}
