import ctypes
import mmap


def create_callable_from_machine_code(machine_code, doc=None, restype=None, argtypes=None, use_errno=False, use_last_error=False):
    if argtypes is None:
        argtypes = []
    exec_code = mmap.mmap(-1, len(machine_code), prot=mmap.PROT_WRITE | mmap.PROT_READ | mmap.PROT_EXEC)
    exec_code.write(machine_code)
    c_type = ctypes.c_byte * len(machine_code)
    c_var = c_type.from_buffer(exec_code)
    address = ctypes.addressof(c_var)
    c_func_factory = ctypes.CFUNCTYPE(restype, *argtypes, use_errno=use_errno, use_last_error=use_last_error)
    func = c_func_factory(address)
    func._exec_code = exec_code # prevent GC of code
    func.__doc__ = doc
    return func


breakpoint = create_callable_from_machine_code(b'\xCC\xC3')

