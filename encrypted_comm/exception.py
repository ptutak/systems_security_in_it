class ShasumError(Exception):
    """
        Raised when the Shasum is not exact.
    """


class InvalidCommand(Exception):
    """
        Raised when the command received was unexpected.
    """


class AuthenticationError(Exception):
    """
        Raised when there was an authentication error.
    """


class ResponseAddressError(Exception):
    """
        Raised when trying to set up the response address for Client Connection
    """


class RegistrationError(Exception):
    """
        Raised upon registration errors.
    """
