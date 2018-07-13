from __future__ import print_function
import pointbreak


# XXX the symbols interface and its interaction wiht breakpoints and traps 
# are WIP
class Tracer:
    def __init__(self):
        self.depth = 0
        self._name_cache = {}

    def trace(self, db):
        address = db.registers.rip
        if address in self._name_cache:
            name = self._name_cache[address]
        else:
            name = db._symbols.address_to_symbols(address)[0].name
            self._name_cache[address] = name
        print("{}{}".format(" " * self.depth, name))
        self.depth += 1
        def trace_exit(db):
            self.depth -= 1
            return False
        if name != '_start': # _start doesn't have a return address - interesting :D
            return_addres = db.stack[0]
            db.add_breakpoint(return_addres, trace_exit, immediately=True)
        return True

tracer = Tracer()
db = pointbreak.create_debugger('python', '-c', 'import itertools')
db.add_breakpoint('.*', tracer.trace)
db.continue_to_last_event()

