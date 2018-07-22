from . import types

# linked list of loaded dynamic libraries see glibc/elf/link.h
link_map_pointer = types.pointer_type(None)
link_map = types.struct_type(
    ('l_addr', types.uint64),
    ('l_name', types.c_string_pointer),
    ('l_ld', types.uint64),
    ('l_next', link_map_pointer),
    ('l_prev', link_map_pointer),
)
link_map_pointer.referenced_type = link_map

r_debug = types.struct_type(
    ('r_version', types.int32),
    ('r_map', link_map_pointer),
    ('r_brk', types.uint64),
    ('r_state', types.int32),
)

