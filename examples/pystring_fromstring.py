from __future__ import print_function
import pointbreak


# XXX the symbols interface and its interaction wiht breakpoints and traps 
# are WIP

def print_string_arg1(db):
    print(repr(db.read_string(db.registers.rdi)))
    return True

db = pointbreak.create_debugger('python', '-c', 'import itertools')
db.add_breakpoint('PyString_FromString$', print_string_arg1)
db.continue_to_last_event()

