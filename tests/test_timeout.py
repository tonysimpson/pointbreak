import pointbreak


def test_master_timeout():
    db = pointbreak.create_debugger('python', '-c', 'import time; time.sleep(0.5)', timeout=.25)
    try:
        db.continue_none_stop()
    except pointbreak.Timeout:
        return
    assert False, "should have raised pointbreak.Timeout"
