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
import shlex
from collections import deque

from . import ptrace
from . import ptraceunwind
from . import process
from .r_debug import r_debug
from . import types
from . import auxv
from .exceptions import Timeout, ExecutableNotFound, PointBreakException, DeadProcess

# XXX work around for long file support
# Man pages seem to be wrong about off64_t being signed
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
    def __init__(self, address, original_byte=None):
        self.address = address
        self.original_byte = original_byte
        self.breakpoints = []

    def is_debugger_inserted(self):
        return self.original_byte is not None

    def is_active(self):
        return len(self.breakpoints) > 0

    def add_breakpoint(self, breakpoint):
        breakpoint.traps.append(self)
        self.breakpoints.insert(0, breakpoint)

    def remove_breakpoint(self, breakpoint, debugger):
        self.breakpoints.remove(breakpoint)
        breakpoint.traps.remove(self)
        if not self.is_active():
            if self.is_debugger_inserted():
                debugger.write(self.address, self.original_byte)

    def trigger(self, debugger):
        still_active_breakpoints = []
        breakpoints = list(self.breakpoints)
        for breakpoint in breakpoints:
            if breakpoint.callback(debugger):
                still_active_breakpoints.append(breakpoint)
            else:
                breakpoint.traps.remove(self)
        self.breakpoints = still_active_breakpoints

    def get_all_not_internal_breakpoints(self):
        return frozenset(bp for bp in self.breakpoints if not bp.internal)

    def remove(self, debugger):
        if self.is_debugger_inserted():
            debugger.write(self.address, self.original_byte)

    def restore(self, debugger):
        if self.is_debugger_inserted():
            debugger.write(self.address, b'\xcc')


class Breakpoint:
    def __init__(self, value, callback, internal=False):
        self.value = value
        self.callback = callback
        self.internal = internal
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
        return "Breakpoint(value={!r}, callback={!r}, internal={!r})".format(self.value, self.callback, self.internal)


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
    def __init__(self, pid, timeout=None):
        self._pid = pid
        self._path = '/proc/%d/exe' % (pid,)
        self._timeout = timeout
        self._mem_fd = os.open("/proc/%d/mem" % (pid,), os.O_RDWR)
        self._symbols = Symbols()
        self._dead = False
        self._breakpoints = []
        self._address_to_trap = {}
        self._active_trap = None
        
        program_entry = auxv.auxv_get_entry(self._pid)
        self._r_debug = None
        self.add_breakpoint(program_entry, Debugger._init_r_debug, immediately=True, internal=True)
        self._cont_signal = 0
        self._unwinder = ptraceunwind.Unwinder(self._pid)
        self._registers = None
        self._statm = Statm(self._pid)
        self._events = deque()

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
                self.add_breakpoint(self._r_debug.r_brk, Debugger._update_dso, immediately=True, internal=True)
                self._update_dso()
                return
            elif tag == ENUM_D_TAG['DT_NULL']:
                raise PointBreakException('No DT_DEBUG')
            r_debug_address += fmt_size 

    def _trigger_trap_event(self, single_stepped=False):
        if single_stepped:
            address = self.registers.rip
        else:
            address = self.registers.rip - 1
        if address in self._address_to_trap:
            trap = self._address_to_trap[address]
            trap.remove(self)
            self.registers.rip = address
            self.save_registers()
            triggered = trap.get_all_not_internal_breakpoints()
            trap.trigger(self)
            if not trap.is_active():
                del self._address_to_trap[address]
            else:
                self._active_trap = trap
            if trap.is_debugger_inserted() and len(triggered) == 0:
                # If all the breakpoints on an inserted trap are internal
                # then don't report the event
                return None
        else:
            triggered = frozenset()
        return Event(EVENT_NAME_TRAP, address=address, triggered=triggered)

    def _trigger_status_events(self, status, single_stepped=False):
        """Take a waitpid status and returns an Event. None if we don't want to surface the event to the user.
        """
        event = None
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if sig == signal.SIGTRAP:
                event = self._trigger_trap_event(single_stepped)
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
        if event is not None:
            self._events.append(event)

    def _check_dead(self):
        if self._dead:
            raise DeadProcess()
    
    def _step_over_active_trap(self, timeout=None):
        trap = self._active_trap
        if trap is not None:
            if trap.address == self.registers.rip:
                if trap.is_debugger_inserted():
                    self._single_step()
                    status = self._wait(timeout=timeout)
                    # do events but ignore the trap caused by single step
                    if not (os.WIFSTOPPED(status) and (os.WSTOPSIG(status) == signal.SIGTRAP)):
                        self._trigger_status_events(status)
                else:
                    #just skip over the breakpoint
                    self.registers.rip += 1
                    self.save_registers()
            trap.restore(self)
            self._active_trap = None

    def next_event(self, timeout=None):
        if self._events:
            return self._events.popleft()
        self._check_dead()
        while True:
            self._step_over_active_trap()
            self._cont()
            status = self._wait(timeout=timeout)
            self._trigger_status_events(status)
            if self._events:
                return self._events.popleft()
    
    def single_step(self, timeout=None):
        self._check_dead()
        # get active trap now as _trigger_status_events might set it
        trap = self._active_trap
        self._active_trap = None
        self._single_step()
        status = self._wait(timeout=timeout)
        self._trigger_status_events(status, True)
        if trap is not None:
            trap.restore(self)
        result = list(self._events)
        self._events.clear()
        return result

    def continue_to_last_event(self, event_timeout=None):
        while True:
            event = self.next_event(timeout=event_timeout)
            if not self._events and self._dead:
                return event

    def raise_event(self, name, **attrs):
        self._check_dead()
        self._events.append(Event(name, **attrs))

    def _install_trap(self, symbol, breakpoint):
        address = breakpoint.address_from_symbol(symbol)
        if address in self._address_to_trap:
            self._address_to_trap[address].add_breakpoint(breakpoint)
        else:
            original_byte = self.read(address, 1)
            if original_byte != b'\xcc':
                self.write(address, b'\xcc')
            else:
                original_byte = None
            trap = Trap(address, original_byte)
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

    def add_breakpoint(self, value, callback=None, immediately=False, internal=False):
        if callback is None:
            callback = lambda db: False
        breakpoint = Breakpoint(value, callback, internal)
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
    def memory_stats(self):
        return self._statm

    @property
    def frame(self):
        return Frame(self, self._unwinder.unwind())

    @property
    def stack(self):
        return Stack(self, self.registers.rsp)
    
    def _wait(self, timeout=None):
        self._registers = None
        if timeout is None:
            timeout = self._timeout
        if timeout is not None:
            st = time.time()
            while time.time() - st < timeout:
                status = os.waitpid(self._pid, os.WNOHANG)
                if status != (0, 0):
                    return status[1]
                time.sleep(0.005) #TODO would be better to use signalfd?
            raise Timeout()
        return os.waitpid(self._pid, 0)[1]

    def read_unmodified(self, offset, byte_len):
        """Read memory at offset for byte_len bytes but without inserted breakpoints

        Any inserted breakpoints (0xcc) are replaced with there original byte.
        """
        ba = bytearray(self.read(offset, byte_len))
        lower = offset
        upper = offset + len(ba)
        for addr, trap in self._address_to_trap.items():
            if trap.original_byte is not None:
                if lower <= addr < upper and trap.original_byte is not None:
                    ba[addr - lower] = trap.original_byte
        return bytes(ba)

    def read(self, offset, byte_len):
        self._check_dead()
        self._seek(offset)
        try:
            b = os.read(self._mem_fd, byte_len)
        except OSError as e:
            raise PointBreakException('Can not read from {} len {} reason: {}'.format(offset, byte_len, e))
        if len(b) != byte_len:
            raise PointBreakException("Incomplete read: read %d wanted %d" % (len(b), byte_len))
        return b

    def write(self, offset, bytes_towrite):
        self._check_dead()
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
        return self.reference(offset, types.c_string).value.decode('utf8', 'replace')

    def read_fmt(self, offset, fmt):
        size = struct.calcsize(fmt)
        b = self.read(offset, size)
        return struct.unpack(fmt, b)

    def write_fmt(self, offset, fmt, *values):
        self.write(offset, struct.pack(fmt, *values))

    def reference(self, offset, mtype):
        return types.reference(mtype, offset, self)

    def signal(self, signal):
        self._check_dead()
        os.kill(self._pid, signal)

    def sigkill(self):
        return self.signal(signal.SIGKILL)

    def sigstop(self):
        return self.signal(signal.SIGSTOP)

    def sigcont(self):
        return self.signal(signal.SIGCONT)

    def backtrace(self):
        self._check_dead()
        result = []
        cur = self.frame
        while cur is not None:
            result.append(cur)
            cur = cur.parent
        result.reverse()
        return result

    def address_to_description(self, address):
        return self._symbols.address_to_description(address)

    def __del__(self):
        if not self._dead:
            self.sigkill()
            self._wait()

    class Iterator:
        def __init__(self, db):
            self.db = db

        def __next__(self):
            if self.db._dead:
                raise StopIteration()
            return self.db.next_event()
        
        next = __next__

    def __iter__(self):
        return Debugger.Iterator(self)


def create_debugger(command, environment=None, timeout=None, disable_randomisation=True, kill_on_exit=True, trap_exit=True):
    split_command = shlex.split(command)
    executable_path, args = split_command[0], split_command[1:]
    if os.path.exists(executable_path): 
        exec_path = executable_path
    if environment is not None:
        env = environment
    else:
        env = dict(os.environ)
    if executable_path.startswith('/') or executable_path.startswith('./'):
        exec_path = executable_path
        if not os.path.exists(exec_path):
            raise ExecutableNotFound('Executable %r does not exist' % (exec_path,))
    else:
        paths = env.get('PATH', '').split(':')
        for path_prefix in paths:
            exec_path = os.path.join(path_prefix, executable_path)
            if os.path.exists(exec_path):
                break
        else:
            ExecutableNotFound('Could not find executable %r in paths %r' % (executable_path, paths))
    exec_abs_path = os.path.abspath(exec_path)
    if not os.path.exists(exec_abs_path):
        raise ExecutableNotFound("Absolute path %r from path %r does not exist" % (exec_abs_path, exec_path))
    child_pid = os.fork()
    if child_pid == 0:
        # I'm the child
        if disable_randomisation:
            process.disable_address_space_randomisation()
        ptrace.trace_me() # Enable tracing
        os.path.basename(exec_path)
        try:
            os.execve(exec_abs_path, [exec_abs_path] + args, env) # Run the debug target
        except Exception as e:
            print("Error on execve. Exiting immediatley:", e)
            os._exit(1)
    else:
        status = os.waitpid(child_pid, 0)[1]
        if os.WIFSIGNALED(status) or os.WIFEXITED(status):
            raise DeadProcess('Child exited before debugger was setup')
        if trap_exit:
            ptrace.set_trace_exit(child_pid)
        if kill_on_exit:
            ptrace.set_exit_kill(child_pid)
        return Debugger(child_pid, timeout=timeout)


__ALL__ = ['create_debugger', 'PointBreakException']

