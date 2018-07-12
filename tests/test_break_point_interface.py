import pointbreak
import pytest

def test_breakpoint_on_main():
    db = pointbreak.create_debugger('python', '--version', timeout=0.5)
    bp = db.add_breakpoint('main')
    event = db.next_event()
    if not event.is_last_event():
        db.continue_none_stop()
    assert event.name == pointbreak.EVENT_NAME_TRAP
    assert bp in event.triggered, "break point should be triggered"

@pytest.mark.skip(reason="We get a STOP Event before the TRAP - need to research why it behaves differently")
def test_existing_breakpoint_in_program():
    db = pointbreak.create_debugger('python', '-c', 'import pointbreak.utils; pointbreak.utils.breakpoint()', timeout=0.5)
    event = db.next_event()
    assert event.name == pointbreak.EVENT_NAME_TRAP
    if not event.is_last_event():
        db.continue_none_stop()

