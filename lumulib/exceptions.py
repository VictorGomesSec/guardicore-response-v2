# Exceptions


# Collector API Exceptions
class NotSupportedEntryTypeException(Exception):
    """
    Thrown when the entry type is not supported
    """


# Defender API Exceptions
class IllegalOperationException(Exception):
    """
    Thrown when an operation is not possible on the Lumu Defender API
    """

    pass


class DeserializationException(Exception):
    """
    Thrown when a request fails because parameter errors
    """

    pass
