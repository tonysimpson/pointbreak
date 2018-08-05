import struct
import pointbreak
import pointbreak.types as types
from pointbreak.types import TestAccessor as Accessor


def test_type_get_simple_value():
    accessor = Accessor(b"\x01\x00\x00\x00")
    ref = types.reference(types.int32, 0, accessor)
    assert ref.value == 1
    

def test_type_set_simple_value():
    accessor = Accessor(b"\x00\x00\x00\x00")
    ref = types.reference(types.int32, 0, accessor)
    ref.value = 22
    assert ref.value == 22

def test_type_get_array_value_unchecked():
    accessor = Accessor(b"\x01\x02\x03")
    uint8_array_unchecked = types.array_type(0, types.uint8, checked=False)
    ref = types.reference(uint8_array_unchecked, 0, accessor)
    assert ref.value[2] == 3

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

def test_pointer_get():
    accessor = Accessor(b"\x08" + (b'\x00' * 7) + b'\x10')
    uint8_pointer = types.pointer_type(types.uint8)
    ref = types.reference(uint8_pointer, 0, accessor)
    assert ref.value.address == 8
    assert ref.value.value == 16

def test_struct():
    accessor = Accessor(b'\x00' * 100)
    complex_struct = types.struct_type(
        ('value', types.int64), 
        ('pvalue', types.pointer_type(types.int64)),
        ('avalue', types.array_type(12, types.char))
    )
    ref = types.reference(complex_struct, 0, accessor)
    ref.value.pvalue = 64
    ref.value.pvalue.value = 32432424
    ref.value.value = 321
    assert ref.value.pvalue.value == 32432424

def test_c_string():
    accessor = Accessor(b"bobbins\x00")
    c_string = types.c_string_type(9)
    ref = types.reference(c_string, 0, accessor)
    assert ref.value == b"bobbins"

