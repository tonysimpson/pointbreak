import os
import sys
import signal
import struct
import re
import pyptrace
import distorm3
from collections import namedtuple
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class


class DebuggingError(Exception):
    pass


class UnknownMapping(Exception):
    pass


_mapping = namedtuple("mapping", "lower upper r w x s p offset device inode pathname".split())
_function = namedtuple("function", "name lower_address upper_address".split())
_line = namedtuple("line", "filename line_number address".split())


def _mapping_file_address_bounds(elf, mapping):
    lower, upper = mapping.offset, mapping.offset + (mapping.upper - mapping.lower)
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_LOAD":
            if lower <= seg.header.p_offset <= upper:
                return (lower, upper), seg.header.p_vaddr
    raise UnknownMapping()

elftools_dwarf_parser_is_too_slow = True

def _extract_symbols(mapping):
    elf = ELFFile(open(mapping.pathname, 'rb'))
    (lower, upper), vaddr = _mapping_file_address_bounds(elf, mapping)
    section = elf.get_section_by_name('.symtab')
    if section is None:
        section = elf.get_section_by_name('.dynsym')
    if section is not None:
        for symbol in section.iter_symbols():
            if symbol.entry.st_info.type == 'STT_FUNC':
                if lower <= (symbol.entry.st_value - vaddr) <= upper:
                    name = symbol.name
                    low_pc = symbol.entry.st_value + mapping.lower - vaddr
                    high_pc = symbol.entry.st_value + symbol.entry.st_size + mapping.lower - vaddr
                    yield _function(name, low_pc, high_pc)
    if not elf.has_dwarf_info() or elftools_dwarf_parser_is_too_slow:
        return
    dwarfinfo = elf.get_dwarf_info()
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_subprogram":
                if 'DW_AT_low_pc' in die.attributes and (lower <= die.attributes['DW_AT_low_pc'].value - vaddr) <= upper:
                    if 'DW_AT_name' in die.attributes:
                        low_pc = die.attributes['DW_AT_low_pc'].value + mapping.lower - vaddr
                        high_pc_class = describe_form_class(die.attributes['DW_AT_high_pc'].form)
                        if high_pc_class == 'address':
                            high_pc = die.attributes['DW_AT_high_pc'].value + mapping.lower - vaddr
                        else:
                            high_pc = die.attributes['DW_AT_high_pc'].value + low_pc
                        name = die.attributes['DW_AT_name'].value
                        yield _function(name, low_pc, high_pc)


def _extract_lines(mapping):
    elf = ELFFile(open(mapping.pathname, 'rb'))
    (lower, upper), vaddr = _mapping_file_address_bounds(elf, mapping)
    if not elf.has_dwarf_info() or elftools_dwarf_parser_is_too_slow:
        return
    dwarfinfo = elf.get_dwarf_info()
    for cu in dwarfinfo.iter_CUs():
        line_program = dwarfinfo.line_program_for_CU(cu)
        for entry in line_program.get_entries():
            if entry.state:
                if lower <= (entry.state.address - vaddr) <= upper:
                    filename = line_program['file_entry'][entry.state.file - 1].name
                    line_number = entry.state.line
                    address = entry.state.address + mapping.lower - vaddr
                    yield _line(filename, line_number, address)


def _maps(pid):
    for line in open("/proc/%d/maps" % (pid,)):
        row = line.split()
        if len(row) > 5:
            pathname = row[5]
        else:
            pathname = None
        if len(row) > 4:
            inode = int(row[4])
        else:
            inode = None
        if len(row) > 3:
            device = row[3]
        else: 
            device = None
        offset = int(row[2], 16)
        _perms = row[1]
        r = _perms[0] != '-'
        w = _perms[1] != '-'
        x = _perms[2] != '-'
        p = _perms[3] == 'p'
        s = _perms[3] == 's'
        _lower, _upper = row[0].split('-', 1)
        lower = int(_lower, 16)
        upper = int(_upper, 16)
        yield _mapping(lower, upper, r, w, x, s, p, offset, device, inode, pathname)
            

class _SymbolsCache:
    def __init__(self):
        self._seen_maps = set()
        self._names_to_functions = {}
        self._files_to_lines = {}

    def register_mapping(self, mapping, debugger):
        if mapping not in self._seen_maps:
            for function in _extract_symbols(mapping):
                for pattern, cb in debugger._breakpoints:
                    if pattern.match(function.name):
                        debugger._install_trap(function.lower_address, cb)
                self._names_to_functions.setdefault(function.name, []).append(function)
            for line in _extract_lines(mapping):
                self._files_to_lines.setdefault(line.filename, []).append(line)
            self._seen_maps.add(mapping)


EVENT_NAME_STOPPED = "STOP"
EVENT_NAME_TRAP = "TRAP"
EVENT_NAME_EXITED = "EXIT"
EVENT_NAME_TERMINATED = "TERM"


class Event:
    def __init__(self, name, **attrs):
        self.name = name
        self._attrs = attrs

    def __getattr__(self, name):
        try:
            return self._attrs[name]
        except KeyError:
            raise AttributeError(name)

    def __repr__(self):
        return "Event(name=%r, **%r)" % (self.name, self._attrs)


class Registers:
    def __init__(self, debugger):
        self.__dict__['_register_names'] = debugger._register_names
        self.__dict__['_gr'] = debugger._get_registers
        self.__dict__['_sr'] = debugger._set_registers

    def __dir__(self):
        return [field for field in self._register_names]

    def __getattr__(self, name):
        return getattr(self._gr(), name)

    def __setattr__(self, name, value):
        regs = self._gr()
        setattr(regs, name, value)
        self._sr(regs)
    
    def __repr__(self):
        regs = self._gr()
        return "Registers(%s)" % (', '.join(["%s=%r" % (field, getattr(regs, field)) for field in self._register_names]), )


class _Debugger:
    def __init__(self, pid, path):
        self._pid = pid
        self._path = path
        self._mem_fd = os.open("/proc/%d/mem" % (pid,), os.O_RDWR)
        self._bp_original_byte = {}
        self._bp_callbacks = {}
        self._sym_cache = _SymbolsCache()
        self._dead = False
        self._breakpoints = []
        self._update_symbols()
        self._restore_trap_address = None
        self._register_names = set(field[0] for field in self._get_registers()._fields_)
    
    def _update_symbols(self):
        for mapping in self._maps():
            if mapping.pathname is not None and os.path.exists(mapping.pathname):
                try:
                    self._sym_cache.register_mapping(mapping, self)
                except UnknownMapping:
                    pass

    def _call_and_reinstall_traps(self):
        regs = self._get_registers()
        address = regs.rip - 1
        if address in self._bp_original_byte:
            # restore the original byte if any
            self._write(address, self._bp_original_byte[address])
            # because we're in a debugger inserted trap also restore rip
            regs.rip = address
            self._set_registers(regs)
        to_reinstall = []
        if address in self._bp_callbacks:
            for cb in self._bp_callbacks[address]:
                if cb(self):
                    to_reinstall.append(cb)
        if to_reinstall:
            # if we have an original then we need to restore the int 3
            if address in self._bp_original_byte:
                self._restore_trap_address = address
            self._bp_callbacks[address] = to_reinstall
        else:
            if address in self._bp_original_byte:
                del self._bp_original_byte[address]
            if address in self._bp_callbacks:
                del self._bp_callbacks[address]
            self._restore_trap_address = None

    def _call_for_event(self, event):
        pass

    def _get_addresses(self, pattern):
        results = set()
        for name, functions in self._sym_cache._names_to_functions.items():
            if pattern.match(name):
                for func in functions:
                    results.add(func.lower_address)
        return list(results)
                
    def next_event(self):
        if self._dead:
            raise DebuggingError("Called next_event after %r or %r Event" % (EVENT_NAME_EXITED, EVENT_NAME_TERMINATED))
        if self._restore_trap_address is not None:
            self._single_step()
            self._wait()
            self._write(self._restore_trap_address, '\xcc')
            self._restore_trap_address = None
        self._cont()
        status = self._wait()
        event = None
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if sig == signal.SIGTRAP:
                event = Event(EVENT_NAME_TRAP)
                self._call_and_reinstall_traps()
            else:
                event = Event(EVENT_NAME_STOPPED, signal=sig)
        elif os.WIFEXITED(status):
            self._dead = True
            exit_status = os.WEXITSTATUS(status)
            event = Event(EVENT_NAME_EXITED, status=exit_status)
        elif os.WIFSIGNALED(status):
            self._dead = True
            sig = os.WTERMSIG(status)
            event = Event(EVENT_NAME_TERMINATED, signal=sig)
        self._call_for_event(event)
        return event
    
    def continue_none_stop(self):
        while True:
            event = self.next_event()
            if event.name in (EVENT_NAME_EXITED, EVENT_NAME_TERMINATED):
                return event

    def _install_trap(self, address, callback):
        original = self._read(address, 1)
        if original != b'\xcc':
            self._bp_original_byte[address] = original
            self._write(address, b'\xcc')
        self._bp_callbacks.setdefault(address, []).append(callback)

    def add_breakpoint(self, pattern, callback):
        if not hasattr('match', pattern):
            pattern = re.compile(pattern)
        self._breakpoints.append((pattern, callback))
        for address in self._get_addresses(pattern):
            self._install_trap(address, callback)

    def _single_step(self):
        pyptrace.singlestep(self._pid)

    def _cont(self):
        pyptrace.cont(self._pid)

    def _get_registers(self):
        return pyptrace.getregs(self._pid)[1]

    def _set_registers(self, registers):
        return pyptrace.setregs(self._pid, registers)

    @property
    def registers(self):
        return Registers(self)

    def _wait(self):
        return os.waitpid(self._pid, 0)[1]

    def _maps(self):
        for mapping in _maps(self._pid):
            yield mapping

    def _read(self, offset, byte_len):
        os.lseek(self._mem_fd, offset, os.SEEK_SET)
        b = os.read(self._mem_fd, byte_len)
        os.lseek(self._mem_fd, 0, os.SEEK_SET)
        if len(b) != byte_len:
            raise DebuggingError("Incomplete read: read %d wanted %d" % (len(b), byte_len))
        return b

    def _write(self, offset, bytes_to_write):
        os.lseek(self._mem_fd, offset, os.SEEK_SET)
        num_written = os.write(self._mem_fd, bytes_to_write)
        os.lseek(self._mem_fd, 0, os.SEEK_SET)
        if num_written != len(bytes_to_write):
            raise DebuggingError("Incomplete write: wrote %d wanted %d" % (num_written, len(bytes_to_write)))

    def read_fmt(self, offset, fmt):
        size = struct.calcsize(fmt)
        b = self._read(offset, size)
        return struct.unpack(fmt, b)

    def write_fmt(self, offset, fmt, *values):
        self._write(offset, struct.pack(fmt, *values))

def create_debugger(executable_path, *args):
    if os.path.exists(executable_path): 
        exec_path = executable_path
    else: # Search the PATH for executable
        for path_prefix in os.environ['PATH'].split(':'):
            exec_path = os.path.join(path_prefix, executable_path)
            if os.path.exists(exec_path):
                break
        else:
            raise DebuggingError('Could not find executable %r' % (executable_path,))
    child_pid = os.fork()
    if child_pid == 0:
        # I'm the child
        pyptrace.traceme() # Enable tracing
        os.execv(exec_path, [os.path.basename(exec_path)] + list(args)) # Run the debug target
    else:
        os.waitpid(child_pid, 0)
        return _Debugger(child_pid, exec_path)


__ALL__ = ['create_debugger', 'DebuggingError']

