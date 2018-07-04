import os
import sys
import signal
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


def _extract_symbols(mapping):
    elf = ELFFile(open(mapping.pathname, 'rb'))
    (lower, upper), vaddr = _mapping_file_address_bounds(elf, mapping)
    if elf.get_section_by_name('.symtab') is not None:
        for symbol in elf.get_section_by_name('.symtab').iter_symbols():
            if symbol.entry.st_info.type == 'STT_FUNC':
                if lower <= (symbol.entry.st_value - vaddr) <= upper:
                    name = symbol.name
                    low_pc = symbol.entry.st_value + mapping.lower - vaddr
                    high_pc = symbol.entry.st_value + symbol.entry.st_size + mapping.lower - vaddr
                    yield _function(name, low_pc, high_pc)
    if not elf.has_dwarf_info():
        return
    dwarfinfo = elf.get_dwarf_info()
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_subprogram":
                if 'DW_AT_low_pc' in die.attributes and (lower <= die.attributes['DW_AT_low_pc'].value - vaddr) <= upper:
                    low_pc = die.attributes['DW_AT_low_pc'].value + mapping.lower - vaddr
                    high_pc_class = describe_form_class(die.attributes['DW_AT_high_pc'].form)
                    if high_pc_class == 'address':
                        high_pc = die.attributes['DW_AT_high_pc'].value + mapping.lower - vaddr
                    else:
                        high_pc = die.attributes['DW_AT_high_pc'].value + low_pc
                    name =  die.attributes['DW_AT_name'].value
                    yield _function(name, low_pc, high_pc)


def _extract_lines(mapping):
    elf = ELFFile(open(mapping.pathname, 'rb'))
    (lower, upper), vaddr = _mapping_file_address_bounds(elf, mapping)
    if not elf.has_dwarf_info():
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

    def register_mapping(self, mapping):
        if mapping not in self._seen_maps:
            for function in _extract_symbols(mapping):
                self._names_to_functions.setdefault(function.name, []).append(function)
            for line in _extract_lines(mapping):
                self._files_to_lines.setdefault(line.filename, []).append(line)
            self._seen_maps.add(mapping)


class _Debugger:
    def __init__(self, pid, path):
        self._pid = pid
        self._path = path
        self._mem_fd = os.open("/proc/%d/mem" % (pid,), os.O_RDWR)
        self._sym_cache = _SymbolsCache()
    
    def _update_symbols(self):
        for mapping in self._maps():
            if mapping.pathname is not None and os.path.exists(mapping.pathname):
                try:
                    self._sym_cache.register_mapping(mapping)
                except UnknownMapping:
                    pass

    def _cont(self):
        pyptrace.cont(self._pid)

    def _wait(self):
        return os.waitpid(self._pid, 0)

    def _maps(self):
        for mapping in _maps(self._pid):
            yield mapping

    def _read(self, offset, byte_len):
        os.lseek(self._mem_fd, offset, os.SEEK_SET)
        b = os.read(self._mem_fd, byte_len)
        os.lseek(self._mem_fd, 0, os.SEEK_SET)
        raise DebuggingError("Incomplete read: read %d wanted %d" % (len(b), byte_len))
        return b

    def _write(self, offset, bytes_to_write):
        os.lseek(self._mem_fd, offset, os.SEEK_SET)
        num_written = os.write(self._mem_fd, bytes_to_write)
        os.lseek(self._mem_fd, 0, os.SEEK_SET)
        if num_written != len(bytes_to_write):
            raise DebuggingError("Incomplete write: wrote %d wanted %d" % (num_written, len(bytes_to_write)))


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

