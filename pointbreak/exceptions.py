

class PointBreakException(Exception):
    pass


class ExecutableNotFound(PointBreakException):
    pass


class Timeout(PointBreakException):
    pass


