import sys
import pointbreak

def test_loading_dynamic_library_and_breaking_on_function():
    db = pointbreak.create_debugger('python  -c "import itertools"', timeout=10)
    # Python 2 and 3 use different conventions for module initialisation
    if sys.version_info < (3,):
        bp = db.add_breakpoint('inititertools')
    else:
        bp = db.add_breakpoint('PyInit_itertools')
    event = db.next_event()
    if not event.is_last_event():
        db.continue_to_last_event()
    assert event.name == pointbreak.EVENT_NAME_TRAP
    assert bp in event.triggered, "break point should be triggered"


