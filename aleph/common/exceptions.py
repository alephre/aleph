##
# Custom exceptions for Aleph components
# ---
# try:
#     do_processor_thing(foo)
# except:
#     raise ProcessorException('Failed to do thing')
##

class BaseException(Exception):
    def __init__(self, exc):
        """Extract exception details and print nicely"""
        super().__init__(exc)


class ProcessorException(BaseException):
    """Handle processing exceptions"""
    def __init__(self, exc):
        pass


class AnalyzerException(BaseException):
    """Handle analyzer exceptions"""
    def __init__(self, exc):
        pass


class StorageException(BaseException):
    """Handle storage exceptions"""
    def __init__(self, exc):
        pass


class CollectorException(BaseException):
    """Handle collector exceptions"""
    def __init__(self, exc):
        pass
