import pointbreak 

def test_loading_dynamic_library_and_breaking_on_function():
    db = pointbreak.create_debugger('python', '-c', 'import itertools', timeout=0.5)
    bp = db.add_breakpoint('inititertools')
    event = db.next_event()
    if not event.is_last_event():
        db.continue_none_stop()
    assert event.name == pointbreak.EVENT_NAME_TRAP
    assert bp in event.triggered, "break point should be triggered"


