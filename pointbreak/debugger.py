from __future__ import print_function, absolute_import
import os
import sys
import signal
import struct
import time
import re
import distorm3
import intervaltree
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG
from elftools.dwarf.descriptions import describe_form_class
import ctypes
import numbers

from . import ptrace
from . import ptraceunwind
from . import process
from .r_debug import r_debug
from . import types
from . import auxv
from .exceptions import Timeout, ExecutableNotFound

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


def extract_symbols(pathname, load_address, use_vaddr=False):
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
        self.tree = intervaltree.IntervalTree()
        self.seen_dso = set()
        self._description_cache = {}

    def _load(self, debugger, pathname, load_address, use_vaddr=False):
        self._description_cache = {}
        for symbol in extract_symbols(pathname, load_address, use_vaddr):
            self.symbols.append(symbol)
            if symbol.low_addr < symbol.high_addr:
                self.tree.addi(symbol.low_addr, symbol.high_addr, symbol)
            if symbol.is_code and symbol.name is not None and symbol.low_addr != 0:
                debugger._new_symbol(symbol)

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
        return self.tree[address]

    def address_to_description(self, address):
        try:
            return self._description_cache[address]
        except:
            symbols = self.address_to_symbols(address)
            if symbols:
                description = ', '.join('{}'.format(i.data.name) for i in symbols)
                self._description_cache[address] = description
                return description
            else:
                return '????@0x{:X}'.format(address)


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
    def __init__(self, debugger, stack_pointer):
        self._d = debugger
        self.stack_pointer = stack_pointer

    def __getitem__(self, key):
        if isinstance(key, slice):
            result = []
            for i in _slice_range(key):
                location = self.stack_pointer + (i * 8)
                result.append(self._d.read_fmt(location, 'Q')[0])
            return result
        location = self.stack_pointer + (key * 8)
        return self._d.read_fmt(location, 'Q')[0]

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            for i, v in zip(_slice_range(key), value):
                location = self.stack_pointer + (i * 8)
                self._d.write_fmt(location, 'Q', v)                
        else:
            location = self.stack_pointer + (key * 8)
            self._d.write_fmt(location, 'Q', value)

    def __repr__(self):
        return "Stack(debugger={!r}, stack_pointer=0x{:X})".format(self._d, self.stack_pointer)


class Trap:
    def __init__(self, address, original_bytes=None):
        self.address = address
        self.original_bytes = original_bytes
        self.breakpoints = []

    def is_user_inserted(self):
        return self.original_bytes is not None

    def is_active(self):
        return len(self.breakpoints) > 0

    def add_breakpoint(self, breakpoint):
        self.breakpoints.insert(0, breakpoint)
        breakpoint.traps.append(self)

    def remove_breakpoint(self, breakpoint, debugger):
        self.breakpoints.remove(breakpoint)
        if not self.is_active():
            if self.is_user_inserted():
                debugger.write(self.address, self.original_bytes)

    def trigger(self, debugger):
        if self.is_user_inserted():
            debugger.write(self.address, self.original_bytes)
            debugger.registers.rip = self.address
            debugger.save_registers()
        still_active_breakpoints = []
        for breakpoint in self.breakpoints:
            if breakpoint.callback(debugger):
                still_active_breakpoints.append(breakpoint)
            else:
                breakpoint.traps.remove(self)
        self.breakpoints = still_active_breakpoints

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
        self.traps = []

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


class FrameRegisters:
    def __init__(self, unwinder_frame):
        self._unwinder_frame = unwinder_frame
    
    for name in dir(ptraceunwind):
        if name.startswith('R'):
            _reg = getattr(ptraceunwind, name)
            def _getter(self, reg=_reg):
                return self._unwinder_frame.get_reg(reg)
            def _setter(self, value, reg=_reg):
                self._unwinder_frame.set_reg(reg)
            prop_name = name.lower()
            locals()[prop_name] = property(_getter, _setter, None, '{} register'.format(prop_name))


class Frame:
    def __init__(self, db, unwinder_frame, child=None):
        self._db = db
        self.child = child
        self._parent = False # use False here as lazy load indicator because parent can be None
        self._registers = None
        self._unwinder_frame = unwinder_frame
    
    @property
    def parent(self):
        if self._parent is False:
            unwinder_frame = self._unwinder_frame.get_parent()
            if unwinder_frame is None:
                self._parent = None
            else:
                self._parent = Frame(self._db, unwinder_frame, self)
        return self._parent
    
    @property
    def registers(self):
        if self._registers is None:
            self._registers = FrameRegisters(self._unwinder_frame)
        return self._registers

    @property
    def function_name(self):
        return self._db.address_to_description(self.registers.rip)

    @property
    def stack(self):
        return Stack(self._db, self.registers.rsp)

    def __repr__(self):
        return '<Frame {}>'.format(self.function_name)


class Statm:
    def __init__(self, pid):
        self._filename = '/proc/%d/statm' % (pid,)

    def _read_statm_field(self, index):
        statm_content = open(self._filename).read()
        field_str = statm_content.split(' ', index+1)[index]
        return int(field_str) * 4096

    @property
    def size(self):
        return self._read_statm_field(0)

    @property
    def resident(self):
        return self._read_statm_field(1)

    @property
    def share(self):
        return self._read_statm_field(2)


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
        
        program_entry = auxv.auxv_get_entry(self._pid)
        self._r_debug = None
        self.add_breakpoint(program_entry, Debugger._init_r_debug, immediately=True, secret=True)
        self._cont_signal = 0
        self._unwinder = ptraceunwind.Unwinder(self._pid)
        self._registers = None
        self._statm = Statm(self._pid)

    def _update_dso(self):
        map_ptr = self._r_debug.r_map
        while map_ptr:
            if map_ptr.value.l_name.value:
                self._symbols.load_dso(self, map_ptr.value.l_name.value.decode('utf8'),  map_ptr.value.l_addr)
            else:
                self._symbols.load_dso(self, self._path,  map_ptr.value.l_addr)
            map_ptr = map_ptr.value.l_next
        return True

    def _init_r_debug(self):
        """Initialise the r_debug structure and set a breakpoint on r_brk to handle share library loads
        
        See glibc/elf/link.h
        """
        fmt = 'QQ'
        fmt_size = struct.calcsize(fmt)
        elf = ELFFile(open(self._path, 'rb'))
        relocation = auxv.auxv_get_entry(self._pid) - elf.header.e_entry
        r_debug_address = elf.get_section_by_name('.dynamic').header['sh_addr'] + relocation
        while True:
            tag, value = self.read_fmt(r_debug_address, fmt)
            if tag == ENUM_D_TAG['DT_DEBUG']:
                if value == 0:
                    raise PointBreakException('DT_DEBUG value is NULL')
                self._r_debug = self.reference(value, r_debug).value
                self.add_breakpoint(self._r_debug.r_brk, Debugger._update_dso, immediately=True, secret=True)
                self._update_dso()
                return
            elif tag == ENUM_D_TAG['DT_NULL']:
                raise PointBreakException('No DT_DEBUG')
            r_debug_address += fmt_size 

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
                self._cont_signal = sig
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
        else:
            addresses = set()
            for symbol in self._symbols.iter_code_symbols():
                if breakpoint.match(symbol):
                    address = breakpoint.address_from_symbol(symbol)
                    if address not in addresses:
                        addresses.add(address)
                        self._install_trap(symbol, breakpoint)

    def remove_breakpoint(self, breakpoint):
        if breakpoint in self._breakpoints: # may not be here because it was applied immediately
            self._breakpoints.remove(breakpoint)
        for trap in breakpoint.traps:
            trap.remove_breakpoint(breakpoint, self)
            if not trap.is_active():
                del self._address_to_trap[trap.address]
        breakpoint.traps = []

    def add_breakpoint(self, value, callback=None, immediately=False, secret=False):
        if callback is None:
            callback = lambda db: False
        breakpoint = Breakpoint(value, callback, secret)
        if not immediately:
            self._breakpoints.append(breakpoint)
        self._new_breakpoint(breakpoint)
        return breakpoint

    def _single_step(self):
        ptrace.single_step(self._pid, 0)

    def _cont(self):
        ptrace.cont(self._pid, self._cont_signal)
        self._cont_signal = 0

    @property
    def registers(self):
        if self._registers is None:
            self._registers = ptrace.get_regs(self._pid)
        return self._registers
    
    def save_registers(self):
        ptrace.set_regs(self._pid, self._registers)

    @property
    def statm(self):
        return self._statm

    @property
    def frame(self):
        return Frame(self, self._unwinder.unwind())

    @property
    def stack(self):
        return Stack(self, self.registers.rsp)


    def _wait(self, timeout=None):
        self._registers = None
        if timeout is None and self._timeout is not None:
            timeout = self._timeout
        if timeout:
            st = time.time()
            while time.time() - st < timeout:
                status = os.waitpid(self._pid, os.WNOHANG)
                if status != (0, 0):
                    return status[1]
                time.sleep(0.005) #TODO would be better to use signalfd?
            raise Timeout()
        return os.waitpid(self._pid, 0)[1]

    def _maps(self):
        for mapping in _maps(self._pid):
            yield mapping

    def read(self, offset, byte_len):
        self._seek(offset)
        try:
            b = os.read(self._mem_fd, byte_len)
        except OSError as e:
            raise PointBreakException('Can not read from {} len {} reason: {}'.format(offset, byte_len, e))
        if len(b) != byte_len:
            raise PointBreakException("Incomplete read: read %d wanted %d" % (len(b), byte_len))
        return b

    def write(self, offset, bytes_towrite):
        self._seek(offset)
        try:
            num_written = os.write(self._mem_fd, bytes_towrite)
        except OSError as e:
            raise PointBreakException('Can not write to {} reason: {}'.format(offset, e))
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

    def signal(self, signal):
        os.kill(self._pid, signal)

    def wait(self):
        status = self._wait()
        return self._do_status_to_event_or_none(status)

    def sigkill(self):
        return self.signal(signal.SIGKILL)

    def sigstop(self):
        return self.signal(signal.SIGSTOP)

    def sigcont(self):
        return self.signal(signal.SIGCONT)

    def kill(self):
        self.sigkill()
        self.wait()

    def backtrace(self):
        result = []
        cur = self.frame
        while cur is not None:
            result.insert(0, cur)
            cur = cur.parent
        return result

    def address_to_description(self, address):
        return self._symbols.address_to_description(address)

    def __del__(self):
        if not self._dead:
            self.kill()

    def __iter__(self):
        return self

    def __next__(self):
        if self._dead:
            raise StopIteration()
        return self.next_event()
    
    next = __next__



def create_debugger(executable_path, *args, **kwargs):
    timeout = None
    if 'timeout' in kwargs:
        timeout = kwargs['timeout']
        del kwargs['timeout']
    disable_address_space_randomisation = True
    if 'disable_address_space_randomisation' in kwargs:
        disable_address_space_randomisation = kwargs['disable_address_space_randomisation']
        del kwargs['disable_address_space_randomisation']
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
        if disable_address_space_randomisation:
            process.disable_address_space_randomisation()
        # I'm the child
        ptrace.trace_me() # Enable tracing
        os.execv(exec_path, [os.path.basename(exec_path)] + list(args)) # Run the debug target
    else:
        os.waitpid(child_pid, 0)
        ptrace.set_exit_kill(child_pid)
        return Debugger(child_pid, exec_path, timeout=timeout)


__ALL__ = ['create_debugger', 'PointBreakException']

