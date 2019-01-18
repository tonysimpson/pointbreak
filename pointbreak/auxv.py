import struct
from . import types

AT_ENTRY = 9

def auxv_get_entry(pid):
    fmt = 'QQ'
    filename = '/proc/%d/auxv' % (pid,)
    auxv = open(filename, 'rb').read()
    size = struct.calcsize(fmt)
    for offset in range(0, len(auxv), size):
        type, value = struct.unpack_from(fmt, auxv, offset)
        if type == AT_ENTRY:
            return value
    raise Exception('Missing AT_ENTRY in %r' % (filename,))

