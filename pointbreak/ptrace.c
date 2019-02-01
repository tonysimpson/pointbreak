#include <Python.h>
#include "structmember.h"
#include <sys/ptrace.h>
#include <sys/user.h>


static PyObject * ptrace_cont(PyObject *self, PyObject *args)
{
    int pid;
    int signal;
    if (!PyArg_ParseTuple(args, "ii", &pid, &signal)) {
        return NULL;
    }
    if (ptrace(PTRACE_CONT, pid, 0, signal) != 0) {
        PyErr_SetString(PyExc_Exception, "ptrace_cont error");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject * ptrace_single_step(PyObject *self, PyObject *args)
{
    int pid;
    int signal;
    if (!PyArg_ParseTuple(args, "ii", &pid, &signal)) {
        return NULL;
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, signal) != 0) {
        PyErr_SetString(PyExc_Exception, "ptrace_single_step error");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject * ptrace_trace_me(PyObject *self, PyObject *args)
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
        PyErr_SetString(PyExc_Exception, "ptrace_trace_me error");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject * ptrace_set_exit_kill(PyObject *self, PyObject *args)
{
    int pid;
    if (!PyArg_ParseTuple(args, "i", &pid)) {
        return NULL;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) != 0) {
        PyErr_SetString(PyExc_Exception, "ptrace_set_exit_kill error");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject * ptrace_set_trace_exit(PyObject *self, PyObject *args)
{
    int pid;
    if (!PyArg_ParseTuple(args, "i", &pid)) {
        return NULL;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT) != 0) {
        PyErr_SetString(PyExc_Exception, "ptrace_set_trace_exit error");
        return NULL;
    }
    Py_RETURN_NONE;
}


typedef struct {
    PyObject_HEAD
    struct user_regs_struct regs;
} PTraceRegisters;

#define PTRTMEMBER(name) { #name, T_ULONGLONG, offsetof(PTraceRegisters, regs) + offsetof(struct user_regs_struct, name), 0, #name }

static PyMemberDef PTraceRegistersType_members[] = {
    PTRTMEMBER(r15),
    PTRTMEMBER(r14),
    PTRTMEMBER(r13),
    PTRTMEMBER(r12),
    PTRTMEMBER(rbp),
    PTRTMEMBER(rbx),
    PTRTMEMBER(r11),
    PTRTMEMBER(r10),
    PTRTMEMBER(r9),
    PTRTMEMBER(r8),
    PTRTMEMBER(rax),
    PTRTMEMBER(rcx),
    PTRTMEMBER(rdx),
    PTRTMEMBER(rsi),
    PTRTMEMBER(rdi),
    PTRTMEMBER(orig_rax),
    PTRTMEMBER(rip),
    PTRTMEMBER(cs),
    PTRTMEMBER(eflags),
    PTRTMEMBER(rsp),
    PTRTMEMBER(ss),
    PTRTMEMBER(fs_base),
    PTRTMEMBER(gs_base),
    PTRTMEMBER(ds),
    PTRTMEMBER(es),
    PTRTMEMBER(fs),
    PTRTMEMBER(gs),
    { NULL, 0, 0, 0, NULL }
};


static PyTypeObject PTraceRegistersType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pointbreak.ptrace.PTraceRegisters", /* tp_name */
    sizeof(PTraceRegisters),   /* tp_basicsize */
    0,                         /* tp_itemsize */
    0,                         /* tp_dealloc */
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
    "Registers Object",        /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    0,                         /* tp_methods */
    PTraceRegistersType_members, /* tp_members */
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


static PyObject * ptrace_register_names(PyObject *self, PyObject *args)
{
    int size = 0;
    int i = 0;
    PyObject *list;
    while (PTraceRegistersType_members[size].name != NULL) {
        size++;
    }
    list = PyList_New(size);
    while(i < size) {
        PyList_SET_ITEM(list, i, PyUnicode_FromString(PTraceRegistersType_members[i].name));
        i++;
    }
    return list;
}


static PyObject * ptrace_get_regs(PyObject *self, PyObject *args)
{
    int pid;
    PTraceRegisters *ptrace_registers;
    if (!PyArg_ParseTuple(args, "i", &pid)) {
        return NULL;
    }
    ptrace_registers = PyObject_New(PTraceRegisters, (PyTypeObject *)&PTraceRegistersType);
    if (ptrace(PTRACE_GETREGS, pid, 0, &ptrace_registers->regs) != 0) {
        PyErr_SetString(PyExc_Exception, "ptrace_get_regs error");
        Py_DECREF(ptrace_registers);
        return NULL;
    }
    return (PyObject*)ptrace_registers;
}


static PyObject * ptrace_set_regs(PyObject *self, PyObject *args)
{
    int pid;
    PTraceRegisters *ptrace_registers;
    if (!PyArg_ParseTuple(args, "iO!", &pid, &PTraceRegistersType, &ptrace_registers)) {
        return NULL;
    }
    if (ptrace(PTRACE_SETREGS, pid, 0, &ptrace_registers->regs) != 0) {
        PyErr_SetString(PyExc_Exception, "ptrace_set_regs error");
        Py_DECREF(ptrace_registers);
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyMethodDef funcs[] = {
    {"cont", ptrace_cont, METH_VARARGS, "Continue traced process"},
    {"single_step", ptrace_single_step, METH_VARARGS, "Single step traced process"},
    {"trace_me", ptrace_trace_me, METH_NOARGS, "Set this process to be traceable by parent"},
    {"set_exit_kill", ptrace_set_exit_kill, METH_VARARGS, "Set traced process to get killed when this process exits"}, 
    {"get_regs", ptrace_get_regs, METH_VARARGS, "Get traced process registers"}, 
    {"set_regs", ptrace_set_regs, METH_VARARGS, "Set traced process registers"}, 
    {"register_names", ptrace_register_names, METH_VARARGS, "List architecture register names"}, 
    {"set_trace_exit", ptrace_set_trace_exit, METH_VARARGS, "Set to get a trace event before tracee exit"},
    {NULL, NULL, 0, NULL}
};


#define MODULE_NAME "pointbreak.ptrace"
#define MODULE_DOC  "Wrapper for ptrace."
#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef module_def = {
   PyModuleDef_HEAD_INIT,
   MODULE_NAME,
   MODULE_DOC,
   0,
   funcs
};

PyMODINIT_FUNC
PyInit_ptrace(void)
#else
void initptrace(void)
#endif
{
    PyObject* m;

    if (PyType_Ready(&PTraceRegistersType) < 0)
        return NULL;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&module_def);
#else
    m = Py_InitModule3(MODULE_NAME, funcs, MODULE_DOC);
#endif
#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}
