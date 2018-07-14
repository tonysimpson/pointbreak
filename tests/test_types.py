import struct
import pointbreak
import pointbreak.types as types


class Accessor:
    def __init__(self, value):
        self.bytes = bytearray(value)

    def read(self, offset, format):
        return struct.unpack_from(format, self.bytes, offset)[0]

    def write(self, offset, format, value):
        struct.pack_into(format, self.bytes, offset, value)


def test_type_get_simple_value():
    accessor = Accessor(b"\x01\x00\x00\x00")
    ref = types.reference(types.int32, 0, accessor)
    assert ref.value == 1
    

def test_type_set_simple_value():
    accessor = Accessor(b"\x00\x00\x00\x00")
    ref = types.reference(types.int32, 0, accessor)
    ref.value = 22
    assert ref.value == 22


def test_type_get_array_value():
    accessor = Accessor(b"\x01\x02\x03")
    uint8_array_3 = types.array_type(3, types.uint8)
    ref = types.reference(uint8_array_3, 0, accessor)
    assert ref.value[0] == 1
    assert ref.value[1] == 2
    assert ref.value[2] == 3


def test_type_set_array_value():
    accessor = Accessor(b"\x00\x00\x00")
    uint8_array_3 = types.array_type(3, types.uint8)
    ref = types.reference(uint8_array_3, 0, accessor)
    ref.value[1] = 5
    assert ref.value[1] == 5


def test_set_whole_array():
    accessor = Accessor(b"\x00\x00\x00\x00\x00")
    uint8_array_5 = types.array_type(5, types.uint8)
    ref = types.reference(uint8_array_5, 0, accessor)
    value = [5,4,3,2,1]
    ref.value = value
    assert list(ref.value) == value

def test_mulitdimensional_array():
    accessor = Accessor(b'\x00\x00\x00\x00\x00\x00')
    uint8_array_3_2 = types.array_type(3, types.array_type(2, types.uint8))
    ref = types.reference(uint8_array_3_2, 0, accessor)
    ref.value[0][0] = 244
    ref.value[2][1] = 221
    assert ref.value[0][0] == 244
    assert ref.value[2][1] == 221

def test_array_detach():
    accessor = Accessor(b"\x00\x01\x00\x05\x00")
    uint8_array_5 = types.array_type(5, types.uint8)
    ref = types.reference(uint8_array_5, 0, accessor)
    assert ref.detach() == [0, 1, 0, 5, 0]

