class RateLimitException(Exception):
    """
    Base Exception
    """

    pass


class NotValidObjectException(RateLimitException):
    """
    Exception raised if no valid object is received by the decorator
    """

    def __init__(self, message="The object received is not supported"):
        super().__init__(message)


class MissingHeaderException(RateLimitException):
    """
    Exception raised if a missing headers is requested
    """
