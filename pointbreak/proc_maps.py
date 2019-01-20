from collections import namedtuple


_mapping = namedtuple("mapping", "lower upper r w x s p offset device inode pathname".split())


def _maps(pid):
    for line in open("/proc/%d/maps" % (pid,)):
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



