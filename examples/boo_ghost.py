from __future__ import print_function
import pointbreak

def print_boo(debugger):
    print("Boo!")
    return True

db = pointbreak.create_debugger('ghost')
db.add_breakpoint('there_is_a_ghost', print_boo)
db.continue_to_last_event()
