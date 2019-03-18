import sys
import traceback


class BaseException(Exception):
    def __init__(self):
        """Extract exception details and print nicely"""
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print(repr(
            traceback.format_exception(exc_type, exc_value, exc_traceback)
            )
        )
        pass


class ProcessorException(BaseException):
    """Handle processing exceptions"""
    pass


class AnalyzerException(BaseException):
    """Handle analyzer exceptions"""
    pass


class StorageException(BaseException):
    """Handle storage exceptions"""
    pass


class CollectorException(BaseException):
    """Handle collector exceptions"""
    pass
