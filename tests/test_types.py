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


def test_type_get_simple_vale():
    accessor = Accessor(b"\x01\x00\x00\x00")
    ref = types.reference(types.int32, 0, accessor)
    assert ref.value == 1
    

def test_type_get_and_set_simple_vale():
    accessor = Accessor(b"\x00\x00\x00\x00")
    ref = types.reference(types.int32, 0, accessor)
    ref.value = 22
    assert ref.value == 22


def test_array_type():
    accessor = Accessor(b"\x01\x02\x03\x00")
    uint8_array_3 = types.array_type(3, types.uint8)
    ref = types.reference(uint8_array_3, 0, accessor)
    assert ref.value[0] == 1
    assert ref.value[1] == 2
    assert ref.value[2] == 3
    ref.value[1] == 5
    assert ref.value[1] == 5


