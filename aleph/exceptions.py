from aleph.mixins.exceptions import ExceptionCauseMixin


class BaseException(ExceptionCauseMixin, Exception):
    """Base exception that all other exceptions will inherit."""

    def __init__(self, exc):
        """Extract exception details and print nicely."""
        super().__init__(exc)


# Component Base Exceptions


class ProcessorException(BaseException):
    """Handle processing exceptions."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class AnalyzerException(BaseException):
    """Handle analyzer exceptions."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class StorageException(BaseException):
    """Handle storage exceptions."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class CollectorException(BaseException):
    """Handle collector exceptions."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class DatastoreException(BaseException):
    """Handle datastore exceptions."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class PluginException(BaseException):
    """Handle plugins general exceptions."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


# Other high-level exceptions
class TemporaryException(BaseException):
    """
    Temporary errors.

    Handle exceptions related to temporary
    issues such as connectivity or concurrency.
    """

    def __init__(self, exc):
        """Initialize exception."""
        pass


# Datastore Exceptions
class DatastoreTemporaryException(TemporaryException, DatastoreException):
    """
    Temporary connection errors.

    Handles exceptions related to temporary conectivity loss
    with the datastore's backend.
    """

    def __init__(self, exc):
        """Initialize exception."""
        pass


class DatastoreStoreException(DatastoreException):
    """Handles exceptions while storing sample on datastore."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class DatastoreRetrieveException(DatastoreException):
    """Handles exceptions while storing sample on datastore."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class DatastoreSearchException(DatastoreException):
    """Handles exceptions while searching on datastore."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


# Processor Exceptions
class ProcessorSetupException(ProcessorException):
    """Handles exceptions caused during the setup of the processor."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class ProcessorRuntimeException(ProcessorException):
    """Handles exceptions caused during the processing."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


# Analyzer Exceptions
class AnalyzerSetupException(AnalyzerException):
    """Handles exceptions caused during the setup of the analyzer."""

    def __init__(self, exc):
        """Initialize exception."""
        pass


class AnalyzerRuntimeException(AnalyzerException):
    """Handles exceptions caused during the analysis."""

    def __init__(self, exc):
        """Initialize exception."""
        pass
