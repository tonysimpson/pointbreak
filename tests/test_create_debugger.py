import pointbreak


def test_create_debug_cat():
    db = pointbreak.create_debugger('cat /dev/null')
    event = db.next_event()
    assert event.name == pointbreak.EVENT_NAME_EXITED


def test_create_debug_no_such_file():
    try:
        pointbreak.create_debugger('zxZUl8a1pp')
    except pointbreak.ExecutableNotFound:
        return
    assert False, "should have raised pointbreak.ExecutableNotFound"

