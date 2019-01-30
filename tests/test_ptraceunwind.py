import pointbreak

def test_ptraceunwind_rip():
    db = pointbreak.create_debugger('cat /dev/null')
    assert db.frame.registers.rip, db.registers.rip


