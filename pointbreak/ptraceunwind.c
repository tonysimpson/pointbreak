#include <libunwind.h>
#include <libunwind-ptrace.h>

#include <Python.h>


static char* libunwind_error_to_string(int error) {
	switch (error * -1) {
		case UNW_EUNSPEC:
            return "unspecified (general) error";
		case UNW_ENOMEM:
            return "out of memory";
		case UNW_EBADREG:
            return "bad register number";
		case UNW_EREADONLYREG:
            return "attempt to write read-only register";
		case UNW_ESTOPUNWIND:
            return "stop unwinding";
		case UNW_EINVALIDIP:
            return "invalid IP";
		case UNW_EBADFRAME:
            return "bad frame";
		case UNW_EINVAL:			
            return "unsupported operation or bad value";
		case UNW_EBADVERSION:	
            return "unwind info has unsupported version";
		case UNW_ENOINFO:		
            return "no unwind info found";
		default: 			
            return "unknown error";
	}
}


typedef struct {
	PyObject_HEAD
    unw_cursor_t cursor;
} Frame;


static PyTypeObject FrameType;


static PyObject*
Frame_get_reg(Frame *self, PyObject *args) {
    unw_word_t value;
    int reg;
    int error;
    if(!PyArg_ParseTuple(args, "i", &reg)) {
        return NULL;
    }
    if((error = unw_get_reg(&self->cursor, reg, &value)) != 0) {
        PyErr_SetString(PyExc_Exception, libunwind_error_to_string(error));
		return NULL;
    }
    return PyLong_FromUnsignedLong(value);
}


static PyObject*
Frame_set_reg(Frame *self, PyObject *args) {
    unw_word_t value;
    int reg;
    int error;
    if(!PyArg_ParseTuple(args, "iK", &reg, &value)) {
        return NULL;
    }
    if((error = unw_set_reg(&self->cursor, reg, value)) != 0) {
        PyErr_SetString(PyExc_Exception, libunwind_error_to_string(error));
		return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject*
Frame_get_parent(Frame *self, PyObject *args)
{
    int error_no;
    Frame *parent;
	if((parent = (Frame*)FrameType.tp_alloc(&FrameType, 0)) == NULL) {
        return NULL;
    }
    memcpy(&parent->cursor, &self->cursor, sizeof(unw_cursor_t));
    if((error_no = unw_step(&parent->cursor)) < 1) {
	    FrameType.tp_free((PyObject*)parent);
		if (error_no == 0) {
             Py_RETURN_NONE; 
		}
        PyErr_SetString(PyExc_Exception, libunwind_error_to_string(error_no));
		return NULL;
    }    
	return (PyObject*)parent;
}        


static void
Frame_dealloc(Frame* self, PyObject *args)
{
	Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyMethodDef Frame_methods[] = {
    {"get_parent", (PyCFunction)Frame_get_parent, METH_NOARGS, "Get frame parent, the outer frame."},
    {"get_reg", (PyCFunction)Frame_get_reg, METH_VARARGS, "Get frame register value."},
    {"set_reg", (PyCFunction)Frame_set_reg, METH_VARARGS, "Set frame register value."},
    {NULL, NULL, 0, NULL}
};


static PyTypeObject FrameType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ptraceunwind.Frame",      /* tp_name */
    sizeof(Frame),             /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)Frame_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    0,                         /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    Frame_methods,             /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};


typedef struct {
    PyObject_HEAD
	unw_addr_space_t addr_space;
	void *unw_init_remote_arg;
} Unwinder;


static PyObject *
Unwinder_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	Unwinder *self = (Unwinder *)type->tp_alloc(type, 0);
	if (self != NULL) {
		long pid;
        static char *kwlist[] = {"pid", NULL};

		if (!PyArg_ParseTupleAndKeywords(args, kwargs, "l", kwlist, &pid)) {
			return NULL;
		}
		if((self->addr_space = unw_create_addr_space(&_UPT_accessors, 0)) == NULL) {
			PyErr_SetString(PyExc_Exception, "unw_create_addr_space failed");
            Py_TYPE(self)->tp_free((PyObject*)self);
			return NULL;
		}
		if((self->unw_init_remote_arg = _UPT_create(pid)) == NULL) {
			PyErr_SetString(PyExc_Exception, "_UPT_create failed");
            unw_destroy_addr_space(self->addr_space);
            Py_TYPE(self)->tp_free((PyObject*)self);
			return NULL;
		}
	}
	return (PyObject*)self;
}


static void
Unwinder_dealloc(Unwinder* self)
{
    unw_destroy_addr_space(self->addr_space);
    _UPT_destroy(self->unw_init_remote_arg);
	Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject *
Unwinder_unwind(Unwinder *self, PyObject *args)
{
    int error_no;
    Frame *frame;
	if((frame = (Frame*)FrameType.tp_alloc(&FrameType, 0)) == NULL) {
        return NULL;
    }
    if((error_no = unw_init_remote(&frame->cursor, self->addr_space, self->unw_init_remote_arg)) != 0) {
	    FrameType.tp_free((PyObject*)frame);
        PyErr_SetString(PyExc_Exception, libunwind_error_to_string(error_no));
		return NULL;
    }    
	return (PyObject*)frame;
}


static PyMethodDef Unwinder_methods[] = {
    {"unwind", (PyCFunction)Unwinder_unwind, METH_NOARGS, "Start unwinding"},
    {NULL, NULL, 0, NULL}
};


static PyTypeObject UnwinderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ptraceunwind.Unwinder",           /* tp_name */
    sizeof(Unwinder),           /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)Unwinder_dealloc,           /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    0,         /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    Unwinder_methods,         /* tp_methods */
    0,         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    Unwinder_new,             /* tp_new */
};


static PyMethodDef funcs[] = {
    {NULL, NULL, 0, NULL}
};


#define MODULE_NAME "pointbreak.ptraceunwind"
#define MODULE_DOC  "Wrapper libunwind's ptrace support."
#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef module_def = {
   PyModuleDef_HEAD_INIT,
   MODULE_NAME,
   MODULE_DOC,
   0,
   funcs
};

PyMODINIT_FUNC
PyInit_ptraceunwind(void)
#else
void initptraceunwind(void)
#endif
{
    PyObject* m;
    if (PyType_Ready(&UnwinderType) < 0) {
        return NULL;
    }
    if (PyType_Ready(&FrameType) < 0) {
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&module_def);
#else
    m = Py_InitModule3(MODULE_NAME, funcs, MODULE_DOC);
#endif
    if (m) {
        #define REG_CONST(T) PyModule_AddIntConstant(m, #T, UNW_X86_64_ ## T)
        REG_CONST(RAX);
        REG_CONST(RBX);
        REG_CONST(RCX);
        REG_CONST(RDX);
        REG_CONST(RDI);
        REG_CONST(RSI);
        REG_CONST(RBP);
        REG_CONST(RSP);
        REG_CONST(R8);
        REG_CONST(R9);
        REG_CONST(R10);
        REG_CONST(R11);
        REG_CONST(R12);
        REG_CONST(R13);
        REG_CONST(R14);
        REG_CONST(R15);
        REG_CONST(RIP);
        Py_INCREF(&UnwinderType);
        PyModule_AddObject(m, "Unwinder", (PyObject *)&UnwinderType);
        Py_INCREF(&FrameType);
        PyModule_AddObject(m, "Frame", (PyObject *)&FrameType);
    }
#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}
