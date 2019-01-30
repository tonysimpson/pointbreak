import pointbreak
import os
import pytest

def test_breakpoint_on_main():
    db = pointbreak.create_debugger('python --version', timeout=20)
    bp = db.add_breakpoint('main')
    event = db.next_event()
    if not event.is_last_event():
        db.continue_to_last_event()
    assert event.name == pointbreak.EVENT_NAME_TRAP
    assert bp in event.triggered, "break point should be triggered"


def test_existing_breakpoint_in_program():
    db = pointbreak.create_debugger('python -c "import pointbreak.utils; pointbreak.utils.breakpoint()"', timeout=20)
    event = db.next_event()
    assert event.name == pointbreak.EVENT_NAME_TRAP
    if not event.is_last_event():
        db.continue_to_last_event()


def test_changing_environment():
    env = dict(os.environ)
    env['VVVV'] = '54'
    db = pointbreak.create_debugger('python -c "import os; exit(int(os.environ.get(\'VVVV\', 31)))"', environment=env, timeout=20)
    e = db.continue_to_last_event()
    assert e.status == 54
