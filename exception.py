class ShasumError(Exception):
    """
        Raised when the Shasum is not exact.
    """


class InvalidCommand(Exception):
    """
        Raised when the command received was unexpected.
    """
