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


class attached_mtype:
    def __init__(self, mtype, offset, accessor):
        self._mtype = mtype
        self._offset = offset
        self._accessor = accessor

    def getter(self):
        return self._accessor.read(self._offset, self._mtype.format)

    def setter(self, value):
        self._accessor.write(self._offset, self._mtype.format, value)

    def detach(self):
        return self.getter()


class array_type:
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
    def __init__(self, array_type, offset, accessor):
        self._array_type = array_type
        self._offset = offset
        self._accessor = accessor

    def __len__(self):
        return self._array_type.length

    def __getitem__(self, index):
        if 0 > index >= len(self):
            raise IndexError('Index error for attached_array')
        offset = self._offset + (index * self._array_type.contained_type.size)
        return self._array_type.attach(offset, self._accessor).getter(None)

    def __setitem__(self, index, value):
        if 0 > index >= len(self):
            raise IndexError('Index error for attached_array')
        offset = self._offset + (index * self._array_type.contained_type.size)
        return self._array_type.attach(offset, self._accessor).setter(None, value)

    def getter(self):
        return self

    def setter(self, value):
        value = list(value)
        if len(value) != self._array_type.length:
            raise TypeError('setter value must be same length as attached_array')
        for num, v in enumerate(value):
            self[num] = v

    def detach(self):
        return [i.detach() for i in self]


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
        pass


class variable_sized_array:
    def __init__(self, size_type, contained_type):
        pass


class reference:
    def __init__(self, mtype, offset, accessor):
        self._attached = mtype.attach(offset, accessor)

    @property
    def value(self):
        return self._attached.getter()
    
    @value.setter
    def value_setter(self, value):
        self._attached.setter(value)
    
    def detach(self):
        self._attached.detach()


char = mtype('char', 'c')
int64 = mtype('int64', 'q')
uint64 = mtype('uint64', 'Q')
int32 = mtype('int32', 'i')
uint32 = mtype('uint32', 'I')
int16 = mtype('int16', 's')
uint16 = mtype('uint16', 'S')
int8 = mtype('int8', 'b')
uint8 = mtype('uint8', 'B')


