import os
import sys
import signal
import pyptrace
import distorm3
from collections import namedtuple



class DebuggingError(Exception):
    pass


_mapping = namedtuple("mapping", "lower upper r w x s p offset device inode pathname".split())


class _Debugger:
    def __init__(self, pid):
        self._pid = pid
        self._mem_fd = os.open("/proc/%d/mem" % (pid,), os.O_RDWR)

    def _cont(self):
        pyptrace.cont(self._pid)

    def _wait(self):
        return os.waitpid(self._pid, 0)

    def _maps(self):
        for line in open("/proc/%d/maps" % (self._pid,)):
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
        return _Debugger(child_pid)


__ALL__ = ['create_debugger', 'DebuggingError']

