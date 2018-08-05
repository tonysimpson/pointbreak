import pointbreak
import pointbreak.ptraceunwind

def test_ptraceunwind_rip():
    db = pointbreak.create_debugger('cat', '/dev/null')
    unwinder = pointbreak.ptraceunwind.Unwinder(db._pid)
    frame = unwinder.unwind()
    assert frame.get_reg(pointbreak.ptraceunwind.RIP) == db.registers.rip

