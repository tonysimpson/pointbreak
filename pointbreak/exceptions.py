

class PointBreakException(Exception):
    pass


class DeadProcess(PointBreakException):
    pass


class ExecutableNotFound(PointBreakException):
    pass


class Timeout(PointBreakException):
    pass


