#include <Python.h>
#include <sys/personality.h>


static PyObject * process_disable_address_space_randomisation(PyObject *self, PyObject *args)
{
    int old_personality;
    old_personality = personality(0xffffffff);
    if(personality(old_personality | ADDR_NO_RANDOMIZE) == -1) {
        PyErr_SetString(PyExc_Exception, "process_disable_address_space_randomisation failed");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyMethodDef funcs[] = {
    {"disable_address_space_randomisation", process_disable_address_space_randomisation, METH_NOARGS, "Disable ASLR for __current__ process. Use after fork."},
    {NULL, NULL, 0, NULL}
};


#define MODULE_NAME "pointbreak.process"
#define MODULE_DOC  "Linux process stuff."
#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef module_def = {
   PyModuleDef_HEAD_INIT,
   MODULE_NAME,
   MODULE_DOC,
   0,
   funcs
};

PyMODINIT_FUNC
PyInit_process(void)
#else
void initprocess(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject* m;
    m = PyModule_Create(&module_def);
#else
    Py_InitModule3(MODULE_NAME, funcs, MODULE_DOC);
#endif
#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}
