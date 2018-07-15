from __future__ import print_function
import os
import sys
import signal
import struct
import time
import re
import pyptrace
import distorm3
from collections import namedtuple
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG
from elftools.dwarf.descriptions import describe_form_class
import ctypes
import numbers

from .r_debug import r_debug
from . import types

# XXX work around for long file support
# Man pages seem to be vague/wrong about off64_t being signed
# https://bugs.python.org/issue12545
lseek64 = ctypes.CDLL('libc.so.6').lseek64
lseek64.restype = ctypes.c_uint64
lseek64.argtypes = [ctypes.c_int, ctypes.c_uint64, ctypes.c_int]
LSEEK64_ERROR = (2 ** 64) - 1
def lseek64_errcheck(result, func, args):
    if result == LSEEK64_ERROR:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return result
lseek64.errcheck = lseek64_errcheck


class PointBreakException(Exception):
    pass


class ExecutableNotFound(PointBreakException):
    pass


class Timeout(PointBreakException):
    pass


_mapping = namedtuple("mapping", "lower upper r w x s p offset device inode pathname".split())

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


class Symbol:
    def __init__(self, low_addr, high_addr=None, name=None, obj_file=None, src_file=None, src_line=None, is_code=False):
        self.low_addr = low_addr
        if high_addr == None:
            high_addr = low_addr
        self.high_addr = high_addr
        self.name = name
        self.obj_file = obj_file
        self.src_file = src_file
        self.src_line = src_line
        self.is_code = is_code

    def __repr__(self):
        return "Symbol(low_addr={!r}, high_addr={!r}, name={!r}, obj_file={!r}, src_file={!r}, src_line={!r}, is_code={!r})".format(self.low_addr, self.high_addr, self.name, self.obj_file, self.src_file, self.src_line, self.is_code)


def extract_symbols(pathname, load_address, use_vaddr=True):
    try:
        elf = ELFFile(open(pathname, 'rb'))
    except:
        return
    if use_vaddr:
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD":
                vaddr = seg.header.p_vaddr
                break
        else:
            raise PointBreakException('Could not find p_vaddr in PT_LOAD segment in file {!r}'.format(pathname))
    else:
        vaddr = 0
    section = elf.get_section_by_name('.symtab')
    if section is None:
        section = elf.get_section_by_name('.dynsym')
    if section is not None:
        for symbol in section.iter_symbols():
            if symbol.entry.st_info.type == 'STT_FUNC':
                name = symbol.name
                low_addr = symbol.entry.st_value + load_address - vaddr
                high_addr = low_addr + symbol.entry.st_size
                yield Symbol(name=name, obj_file=pathname, low_addr=low_addr, high_addr=high_addr, is_code=True)


class Symbols:
    def __init__(self):
        self.symbols = []
        self.seen_dso = set()

    def _load(self, debugger, pathname, load_address, use_vaddr=True):
        for symbol in extract_symbols(pathname, load_address, use_vaddr):
            self.symbols.append(symbol)
            if symbol.is_code and symbol.name is not None and symbol.low_addr != 0:
                debugger._new_symbol(symbol)

    def load_program(self, debugger, pathname):
        self._load(debugger, pathname, 0, use_vaddr=False)

    def load_dso(self, debugger, pathname, load_address):
        if pathname in self.seen_dso:
            return
        self.seen_dso.add(pathname)
        self._load(debugger, pathname, load_address)

    def iter_code_symbols(self):
        for symbol in self.symbols:
            if symbol.is_code and symbol.name is not None and symbol.low_addr != 0:
                yield symbol

    def address_to_symbols(self, address):
        return [sym for sym in self.symbols if sym.low_addr <= address < sym.high_addr]


EVENT_NAME_STOPPED = "STOP"
EVENT_NAME_TRAP = "TRAP"
EVENT_NAME_EXITED = "EXIT"
EVENT_NAME_TERMINATED = "TERM"


class Event:
    def __init__(self, name, **attrs):
        self.name = name
        self._attrs = attrs

    def is_last_event(self):
        return self.name in (EVENT_NAME_EXITED, EVENT_NAME_TERMINATED)

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
        return "Registers({})".format(', '.join(["{}=0x{:X}".format(field, getattr(regs, field)) for field in self._register_names]))


def _all_not_none(*args):
    return all(i is not None for i in args)


def _slice_range(slice):
    if _all_not_none(slice.start, slice.stop, slice.step):
        return range(slice.start, slice.stop, slice.step)
    elif _all_not_none(slice.start, slice.stop):
        return range(slice.start, slice.stop)
    elif _all_not_none(slice.end, slice.step):
        return range(0, slice.end, slice.step)
    elif _all_not_none(slice.end):
        return range(0, slice.end)
    raise PointBreakException('Invalid slice for stack {!r}'.format(slice))


class Stack:
    def __init__(self, debugger):
        self._d = debugger

    def __getitem__(self, key):
        rsp = self._d.registers.rsp
        if isinstance(key, slice):
            result = []
            for i in _slice_range(key):
                location = rsp + (i * 8)
                result.append(self._d.read_fmt(location, 'Q')[0])
            return result
        location = rsp + (key * 8)
        return self._d.read_fmt(location, 'Q')[0]

    def __setitem__(self, key, value):
        rsp = self._d.registers.rsp
        if isinstance(key, slice):
            for i, v in zip(_slice_range(key), value):
                location = rsp + (i * 8)
                self._d.write_fmt(location, 'Q', v)                
        else:
            location = rsp + (key * 8)
            self._d.write_fmt(location, 'Q', value)

    def __repr__(self):
        return "Stack(rsp=0x{:X})".format(self._d.registers.rsp)


class Trap:
    def __init__(self, address, original_bytes=None):
        self.address = address
        self.original_bytes = original_bytes
        self.breakpoints = set()

    def is_user_inserted(self):
        return self.original_bytes is not None

    def is_active(self):
        return len(self.breakpoints) > 0

    def add_breakpoint(self, breakpoint):
        self.breakpoints.add(breakpoint)

    def trigger(self, debugger):
        if self.is_user_inserted():
            debugger.write(self.address, self.original_bytes)
            debugger.registers.rip = self.address
        for breakpoint in list(self.breakpoints):
            if not breakpoint.callback(debugger):
                self.breakpoints.remove(breakpoint)

    def get_all_not_secret_breakpoints(self):
        return frozenset(bp for bp in self.breakpoints if not bp.secret)
    
    def step_and_restore(self, debugger):
        if self.is_user_inserted():
            debugger._single_step()
            debugger._wait()
            debugger.write(self.address, b'\xcc')


class Breakpoint:
    def __init__(self, value, callback, secret=False):
        self.value = value
        self.callback = callback
        self.secret = secret
        self._re_pattern = None
        self._address = None
        if isinstance(value, numbers.Number):
            self._address = int(value)
        else:
            self._re_pattern = re.compile(value)

    def address_from_symbol(self, symbol):
        if self._address is not None:
            return self._address
        return symbol.low_addr

    def match(self, symbol):
        if symbol is None:
            if self._address is not None:
                return True
            else:
                return False
        if self._re_pattern is not None and symbol.name is not None:
            m = self._re_pattern.match(symbol.name)
            if m and m.end() == len(symbol.name):
                return True
        if self._address is not None:
            if symbol.low_addr <= self._address < symbol.high_addr:
                return True
        return False

    def __repr__(self):
        return "Breakpoint(value={!r}, callback={!r}, secret={!r})".format(self.value, self.callback, self.secret)


class Debugger:
    def __init__(self, pid, path, timeout=None):
        self._pid = pid
        self._path = path
        self._timeout = timeout
        self._mem_fd = os.open("/proc/%d/mem" % (pid,), os.O_RDWR)
        self._symbols = Symbols()
        self._dead = False
        self._breakpoints = []
        self._address_to_trap = {}
        self._active_trap = None
        self._symbols.load_program(self, self._path)
        self._r_debug = None
        self.add_breakpoint('main', Debugger._init_r_debug, immediately=True, secret=True)
        self._register_names = set(field[0] for field in self._get_registers()._fields_)

    def _update_dso(self):
        map_ptr = self._r_debug.r_map
        while map_ptr:
            if map_ptr.value.l_name:
                self._symbols.load_dso(self, map_ptr.value.l_name.value.decode('utf8'),  map_ptr.value.l_addr)
            map_ptr = map_ptr.value.l_next
        return True

    def _init_r_debug(self):
        """Initialise the r_debug structure and set a breakpoint on r_brk to handle share library loads
        
        See glibc/elf/link.h
        """
        elf = ELFFile(open(self._path, 'rb'))
        address = elf.get_section_by_name('.dynamic').header['sh_addr']
        while True:
            tag, value = self.read_fmt(address, 'QQ')
            if tag == ENUM_D_TAG['DT_DEBUG']:
                if value == 0:
                    raise PointBreakException('DT_DEBUG value is NULL')
                self._r_debug = self.reference(value, r_debug).value
                self.add_breakpoint(self._r_debug.r_brk, Debugger._update_dso, immediately=True, secret=True)
                return
            elif tag == ENUM_D_TAG['DT_NULL']:
                raise PointBreakException('No DT_DEBUG')
            address += struct.calcsize('QQ')

    def _restore_current_trap_if_needed(self):
        if self._active_trap is not None:
            self._active_trap.step_and_restore(self)
            self._active_trap = None

    def _do_trap_event(self):
        address = self.registers.rip - 1
        if address in self._address_to_trap:
            trap = self._address_to_trap[address]
            triggered = trap.get_all_not_secret_breakpoints()
            trap.trigger(self)
            if not trap.is_active():
                del self._address_to_trap[address]
            else:
                self._active_trap = trap
            if trap.is_user_inserted() and len(triggered) == 0:
                # XXX is_user_inserted should be is_debugger_inserted
                #
                # If all the breakpoints on an inserted trap are secret
                # then don't report the event
                return None
        else:
            triggered = frozenset()
        return Event(EVENT_NAME_TRAP, address=address, triggered=triggered)

    def _do_status_to_event_or_none(self, status):
        """Take a waitpid status and returns an Event. None if we don't want to surface the event to the user.
        """
        event = None
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if sig == signal.SIGTRAP:
                event = self._do_trap_event()
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
        return event

    def next_event(self, timeout=None):
        if self._dead:
            raise PointBreakException("Called next_event after %r or %r Event" % (EVENT_NAME_EXITED, EVENT_NAME_TERMINATED))
        while True:
            self._restore_current_trap_if_needed()
            self._cont()
            status = self._wait(timeout=timeout)
            event = self._do_status_to_event_or_none(status)
            if event is not None:
                return event
    
    def single_step(self, timeout=None):
        if self._dead:
            raise PointBreakException("Called single_step after %r or %r Event" % (EVENT_NAME_EXITED, EVENT_NAME_TERMINATED))
        self._single_step()
        status = self._wait(timeout=timeout)
        return self._do_status_to_event_or_none(status)

    def continue_to_last_event(self, timeout=None):
        while True:
            event = self.next_event(timeout=timeout)
            if event.is_last_event():
                return event

    def _install_trap(self, symbol, breakpoint):
        address = breakpoint.address_from_symbol(symbol)
        if address in self._address_to_trap:
            self._address_to_trap[address].add_breakpoint(breakpoint)
        else:
            original_bytes = self.read(address, 1)
            if original_bytes != b'\xcc':
                self.write(address, b'\xcc')
            else:
                original_bytes = None
            trap = Trap(address, original_bytes)
            trap.add_breakpoint(breakpoint)
            self._address_to_trap[address] = trap

    def _new_symbol(self, symbol):
        # XXX should uninstall traps with address is in symbol here?
        # needs some work
        for breakpoint in self._breakpoints:
            if breakpoint.match(symbol):
                self._install_trap(symbol, breakpoint)

    def _new_breakpoint(self, breakpoint):
        if breakpoint.match(None):
            self._install_trap(None, breakpoint)
        for symbol in self._symbols.iter_code_symbols():
            if breakpoint.match(symbol):
                self._install_trap(symbol, breakpoint)

    def add_breakpoint(self, value, callback=None, immediately=False, secret=False):
        if callback is None:
            callback = lambda db: False
        breakpoint = Breakpoint(value, callback, secret)
        if not immediately:
            self._breakpoints.append(breakpoint)
        self._new_breakpoint(breakpoint)
        return breakpoint

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

    @property
    def stack(self):
        return Stack(self)

    def _wait(self, timeout=None):
        if timeout is None and self._timeout is not None:
            timeout = self._timeout
        if timeout:
            st = time.time()
            while time.time() - st < timeout:
                status = os.waitpid(self._pid, os.WNOHANG)
                if status != (0, 0):
                    return status[1]
                time.sleep(0.005)
            raise Timeout()
        return os.waitpid(self._pid, 0)[1]

    def _maps(self):
        for mapping in _maps(self._pid):
            yield mapping

    def read(self, offset, byte_len):
        self._seek(offset)
        b = os.read(self._mem_fd, byte_len)
        if len(b) != byte_len:
            raise PointBreakException("Incomplete read: read %d wanted %d" % (len(b), byte_len))
        return b

    def write(self, offset, bytes_towrite):
        self._seek(offset)
        num_written = os.write(self._mem_fd, bytes_towrite)
        if num_written != len(bytes_towrite):
            raise PointBreakException("Incomplete write: wrote %d wanted %d" % (num_written, len(bytes_towrite)))
  
    def _seek(self, offset):
        if offset <= 9223372036854775807: # MAX_LONG
            return os.lseek(self._mem_fd, offset, os.SEEK_SET)
        else:
            return lseek64(self._mem_fd, offset, os.SEEK_SET)

    def read_string(self, offset):
        return self.reference(offset, types.c_string).value.decode('utf8')

    def read_fmt(self, offset, fmt):
        size = struct.calcsize(fmt)
        b = self.read(offset, size)
        return struct.unpack(fmt, b)

    def write_fmt(self, offset, fmt, *values):
        self.write(offset, struct.pack(fmt, *values))

    def reference(self, offset, mtype):
        return types.reference(mtype, offset, self)

    def kill(self):
        if not self._dead:
            os.kill(self._pid, signal.SIGKILL)
            status = self._wait()
            return self._do_status_to_event_or_none(status)
        raise PointBreakException("Called kill after %r or %r Event" % (EVENT_NAME_EXITED, EVENT_NAME_TERMINATED))

    def __del__(self):
        self.kill()

    def __iter__(self):
        return self

    def __next__(self):
        if self._dead:
            return StopIteration()
        return self.next_event()
    
    next = __next__



def create_debugger(executable_path, *args, **kwargs):
    timeout = None
    if 'timeout' in kwargs:
        timeout = kwargs['timeout']
        del kwargs['timeout']
    if kwargs:
        raise TypeError('Unexpected keyword arguments {!r}'.format(kwargs))
    if os.path.exists(executable_path): 
        exec_path = executable_path
    else: # Search the PATH for executable
        for path_prefix in os.environ['PATH'].split(':'):
            exec_path = os.path.join(path_prefix, executable_path)
            if os.path.exists(exec_path):
                break
        else:
            raise ExecutableNotFound('Could not find executable %r' % (executable_path,))
    child_pid = os.fork()
    if child_pid == 0:
        # I'm the child
        pyptrace.traceme() # Enable tracing
        os.execv(exec_path, [os.path.basename(exec_path)] + list(args)) # Run the debug target
    else:
        os.waitpid(child_pid, 0)
        pyptrace.setoptions(child_pid, pyptrace.PTRACE_O_EXITKILL)
        return Debugger(child_pid, exec_path, timeout=timeout)


__ALL__ = ['create_debugger', 'PointBreakException']

