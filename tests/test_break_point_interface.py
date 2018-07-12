import pointbreak

def test_breakpoint_on_main():
    db = pointbreak.create_debugger('python', '--version', timeout=0.5)
    bp = db.add_breakpoint('main')
    event = db.next_event()
    if not event.is_last_event():
        db.continue_none_stop()
    assert event.name == pointbreak.EVENT_NAME_TRAP
    assert bp in event.triggered, "break point should be triggered"
