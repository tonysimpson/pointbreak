import struct as _struct


class TestAccessor(object):
    def __init__(self, value):
        self.bytes = bytearray(value)

    def read(self, offset, size):
        return self.bytes[offset:offset+size]

    def write(self, offset, bytes_to_write):
        self.bytes[offset:offset+len(bytes_to_write)] = bytes_to_write

    def read_fmt(self, offset, format):
        return _struct.unpack_from(format, self.bytes, offset)

    def write_fmt(self, offset, format, value):
        _struct.pack_into(format, self.bytes, offset, value) 


class Invalid:
    __slots__ = ('attached',)

    def __init__(self, attached):
        self.attached = attached

    def __repr__(self):
        return 'Invalid(attached={!r})'.format(self.attached)


class mtype(object):
    def __init__(self, name, format):
        self.name = name
        self.format = format
        self._alignment = _struct.calcsize(self.format)
        self._size = _struct.calcsize(self.format)
    
    @property
    def alignment(self):
        return self._alignment

    @property
    def size(self):
        return self._size

    def attach(self, offset, accessor):
        return attached_mtype(self, offset, accessor)


class attached_mtype(object):
    def __init__(self, mtype, offset, accessor):
        self._mtype = mtype
        self._offset = offset
        self._accessor = accessor

    def getter(self):
        return self._accessor.read_fmt(self._offset, self._mtype.format)[0]

    def setter(self, value):
        self._accessor.write_fmt(self._offset, self._mtype.format, value)

    def detach(self):
        try:
            return self.getter()
        except:
            return Invalid(self)


class array_type(object):
    def __init__(self, length, contained_type, checked=True):
        self.length = length
        self.contained_type = contained_type
        self.checked = checked

    @property
    def alignment(self):
        return self.contained_type.alignment

    @property
    def size(self):
        return self.contained_type.size * self.length

    def attach(self, offset, accessor):
        return attached_array(self, offset, accessor)


class offset(object):
    def __init__(self):
        self.alignment = 1
        self.size = 1

    def attach(self, offset, accessor):
        return attached_offset(offset, accessor)


class attached_offset(object):
    def __init__(self, offset, accessor):
        self.offset = offset
        self.accessor = accessor

    def read(self, size):
        return self.accessor.read(self.offset, size)

    def getter(self):
        return self

    def setter(self, value):
        raise Exception("Can not set offset")

    def detach(self):
        raise Exception("Can not detach offset")


class attached_array(object):
    def __init__(self, array_type, offset, accessor):
        self._array_type = array_type
        self._offset = offset
        self._accessor = accessor

    def __len__(self):
        return self._array_type.length

    def __getitem__(self, index):
        if self._array_type.checked:
            if index < 0 or index >= len(self):
                raise IndexError('Index error for attached_array')
        offset = self._offset + (index * self._array_type.contained_type.size)
        return self._array_type.contained_type.attach(offset, self._accessor).getter()

    def __setitem__(self, index, value):
        if self._array_type.checked:
            if index < 0 or index >= len(self):
                raise IndexError('Index error for attached_array')
        offset = self._offset + (index * self._array_type.contained_type.size)
        return self._array_type.contained_type.attach(offset, self._accessor).setter(value)

    def getter(self):
        return self

    def setter(self, value):
        value = list(value)
        if len(value) != self._array_type.length:
            raise TypeError('setter value must be same length as attached_array')
        for num, v in enumerate(value):
            self[num] = v

    def detach(self):
        results = []
        for i in range(len(self)):
            offset = self._offset + (i * self._array_type.contained_type.size)
            v = self._array_type.contained_type.attach(offset, self._accessor).detach()
            results.append(v)
        return results


class struct_type(object):
    def __init__(self, *fields):
        self.fields = fields
        size = 0
        for name, mtype in fields:
            size += size % mtype.alignment
            size += mtype.size
        self._size = size
        self._alignment = self.fields[0][1].alignment

    @property
    def alignment(self):
        return self._alignment

    @property
    def size(self):
        return self._size

    def attach(self, offset, accessor):
        return attached_struct(self, offset, accessor)


class Struct(object):
    def __init__(self, fields):
        self._fields = fields
        self.__dict__.update(fields)

    def __repr__(self):
        return 'Struct({})'.format(', '.join('{}={!r}'.format(name, value) for name, value in self._fields.items()))


class attached_struct(object):
    def __init__(self, struct_type, offset, accessor):
        self.__dict__['_struct_type'] = struct_type
        self.__dict__['_offset'] = offset
        self.__dict__['_accessor'] = accessor
        self.__dict__['_attached_fields'] = {}
        struct_offset = 0
        for name, value in struct_type.fields:
            struct_offset += struct_offset % value.alignment
            self._attached_fields[name] = value.attach(offset + struct_offset, accessor)
            struct_offset += value.size

    def __repr__(self):
        return "attached_struct(struct_type={!r}, offset={!r}, accessor={!r})".format(
            self._struct_type,
            self._offset,
            self._accessor,
            self._attached_fields
        )

    def __dir__(self):
        return [name for name in self._attached_fields]

    def __getattr__(self, name):
        return self._attached_fields[name].getter()

    def __setattr__(self, name, value):
        self._attached_fields[name].setter(value)
    
    def getter(self):
        return self

    def setter(self, value):
        for attr in dir(self):
            if hasattr(value, attr):
                setattr(self, attr, getattr(value, attr))

    def detach(self):
        detached_fields = {}
        for name in dir(self):
            detached_fields[name] = self._attached_fields[name].detach()
        return Struct(detached_fields)


class pointer_type(object):
    def __init__(self, referenced_type):
        self.referenced_type = referenced_type
        self._size = _struct.calcsize('P')
        self._alignment = self._size

    @property
    def alignment(self):
        return self._alignment

    @property
    def size(self):
        return self._size

    def attach(self, offset, accessor):
        return attached_pointer(self, offset, accessor)


class AttachedPointer(object):
    def __init__(self, address, attached_value):
        self.address = address
        self._attached_value = attached_value

    @property
    def value(self):
        return self._attached_value.getter()

    @value.setter
    def value(self, value):
        self._attached_value.setter(value)


class Pointer(object):
    def __init__(self, address, value):
        self.address = address
        self.value = value

    def __repr__(self):
        return "Pointer(address={!r}, value={!r})".format(self.address, self.value)


class attached_pointer(object):
    def __init__(self, pointer_type, offset, accessor):
        self._pointer_type = pointer_type
        self._offset = offset
        self._accessor = accessor

    def getter(self):
        address, = self._accessor.read_fmt(self._offset, 'P')
        if address == 0:
            return None
        attached = self._pointer_type.referenced_type.attach(address, self._accessor)
        return AttachedPointer(address, attached)

    def setter(self, value):
        self._accessor.write_fmt(self._offset, 'P', value)

    def detach(self):
        try:
            address, = self._accessor.read_fmt(self._offset, 'P')
        except:
            return Invalid(self)
        if address == 0:
            return None
        attached = self._pointer_type.referenced_type.attach(address, self._accessor)
        return Pointer(address, attached.detach())


class c_string_type(object):
    def __init__(self, known_size):
        self._size = known_size
    
    @property
    def alignment(self):
        return 1

    @property
    def size(self):
        return self._size

    def attach(self, offset, accessor):
        return attached_c_string(self, offset, accessor)


class attached_c_string(object):
    def __init__(self, c_string_type, offset, accessor):
        self._c_string_type = c_string_type
        self._offset = offset
        self._accessor = accessor
    
    def getter(self):
        buffer = []
        offset = self._offset
        while True:
            c, = self._accessor.read_fmt(offset, 'c')
            offset += 1
            if c == b'\x00':
                return b''.join(buffer)
            buffer.append(c)

    def setter(self, value):
        offset = self._offset
        strlen = min(len(value), self._c_string_type.size - 1)
        if strlen <= 0:
            return
        for i in range(strlen):
            self._accessor.write_fmt(self._offset + i, 'c', value[i])
        self._accessor.write_fmt(self._offset + strlen, 'b', 0)

    def detach(self):
        try:
            return self.getter()
        except:
            return Invalid(self)


class reference(object):
    def __init__(self, mtype, offset, accessor):
        self._attached = mtype.attach(offset, accessor)

    @property
    def value(self):
        return self._attached.getter()
    
    @value.setter
    def value(self, value):
        self._attached.setter(value)
    
    def detach(self):
        return self._attached.detach()

c_string = c_string_type(0)
c_string_pointer = pointer_type(c_string)
char = mtype('char', 'c')
int64 = mtype('int64', 'q')
uint64 = mtype('uint64', 'Q')
int32 = mtype('int32', 'i')
uint32 = mtype('uint32', 'I')
int16 = mtype('int16', 'h')
uint16 = mtype('uint16', 'H')
int8 = mtype('int8', 'b')
uint8 = mtype('uint8', 'B')


