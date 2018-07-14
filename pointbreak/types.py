import struct


class mtype:
    def __init__(self, name, format):
        self.name = name
        self.format = format
        self._alignment = struct.calcsize(self.format)
        self._size = struct.calcsize(self.format)
    
    @property
    def alignment(self):
        return self._alignment

    @property
    def size(self):
        return self._size

    def attach(self, offset, accessor):
        return attached_mtype(self, offset, accessor)


class array:
    def __init__(self, length, contained_type):
        self.length = length
        self.contained_type = contained_type

    @property
    def alignment(self):
        return self.contained_type.alignment

    @property
    def size(self):
        return self.contained_type.size * self.length

    def attach(self, offset, accessor):
        return attached_array(self, offset, accessor)

class attached_array:
    def __init__(self, mtype, offset, accessor):
        self._mtype = mtype
        self._offset = offset
        self._accessor = accessor

    def getter(self, ref):
        return self._accessor.read(self._offset, self._mtype.format)

    def setter(self, ref, value):
        self._accessor.write(self._offset, self._mtype.format, value)

    def detach(self, ref):
        return self.getter(ref)



class struct:
    def __init__(self, *fields):
        pass


class union:
    def __init__(self, *fields):
        pass


class field:
    def __init__(self, mtype):
        pass


class null_term_string:
    def __init__(self):
        


class variable_sized_array:
    def __init__(self, size_type, contained_type):
        pass




class attached_mtype:
    def __init__(self, mtype, offset, accessor):
        self._mtype = mtype
        self._offset = offset
        self._accessor = accessor

    def getter(self, ref):
        return self._accessor.read(self._offset, self._mtype.format)

    def setter(self, ref, value):
        self._accessor.write(self._offset, self._mtype.format, value)

    def detach(self, ref):
        return self.getter(ref)


def reference(mtype, offset, accessor):
    attached = mtype.attach(offset, accessor)
    class Ref:
        value = property(attached.getter, attached.setter)
        detach = attached.detach
    return Ref()


char = mtype('char', 'c')
int64 = mtype('int64', 'q')
uint64 = mtype('uint64', 'Q')
int32 = mtype('int32', 'i')
uint32 = mtype('uint32', 'I')
int16 = mtype('int16', 's')
uint16 = mtype('uint16', 'S')
int8 = mtype('int8', 'b')
uint8 = mtype('uint8', 'B')


