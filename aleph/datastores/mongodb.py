import logging

from pymongo import MongoClient

from aleph.config.constants import (
    FIELD_SAMPLE_ANALYZER_ITEMS,
    FIELD_SAMPLE_FILETYPE,
    FIELD_SAMPLE_FILETYPE_DESC,
    FIELD_SAMPLE_IOCS,
    FIELD_SAMPLE_PROCESSOR_ITEMS,
    FIELD_SAMPLE_SIZE,
    FIELD_SAMPLE_TIMESTAMP,
)
from aleph.exceptions import (
    DatastoreRetrieveException,
    DatastoreSearchException,
    DatastoreStoreException,
    DatastoreTemporaryException,
)
from aleph.helpers.iocs import default_values as ioc_default_values
from aleph.models import Datastore

class MongoDB(Datastore):

    default_options = {
        "connection_url": "mongodb://localhost:27017",
        "database": "aleph",
        "samples_table": "samples",
        "tracking_table": "tracking",
    }

    engine = None
    database = None
    samples_table = None
    tracking_table = None

    def setup(self):
        try:
            connection_url = self.options.get("connection_url")

            self.logger.debug(f"Connecting to MongoDB at {connection_url}")

            # Connect to MongoDB and load database
            self.engine = MongoClient(connection_url)
            self.database = self.engine[self.options.get("database")]

            # Load table references
            self.samples_table = self.database[self.options.get("samples_table")]
            self.tracking_table = self.database[self.options.get("tracking_table")]

            self.logger.debug("Connected to MongoDB")

        except Exception as e:
            self.logger.error("Error setting up MongoDB datastore: %s" % str(e))

    def _get(self, sample_id):

        try:
            return self.samples_table.find_one({"_id", sample_id})
        except Exception as e:
            raise DatastoreRetrieveException(e)

    def retrieve(self, sample_id):

        try:
            self.logger.debug("Retrieving metadata for %s" % sample_id)
            result = self._get(sample_id)
            self.logger.debug("Metadata retrieved for %s" % sample_id)
            return result
        except (DatastoreTemporaryException, DatastoreRetrieveException) as e:
            raise e
        except Exception as e:
            raise DatastoreRetrieveException(e)

    def store(self, sample_id, document):

        self.logger.debug("Storing sample %s on datastore" % sample_id)

        try:

            default_values = {
                FIELD_SAMPLE_TIMESTAMP: None,
                FIELD_SAMPLE_SIZE: 0,
                FIELD_SAMPLE_FILETYPE: None,
                FIELD_SAMPLE_FILETYPE_DESC: None,
                FIELD_SAMPLE_PROCESSOR_ITEMS: {},
                FIELD_SAMPLE_ANALYZER_ITEMS: {},
                FIELD_SAMPLE_IOCS: ioc_default_values,
            }

            document_body = {**default_values, **document}

            self._update(sample_id, document_body, table=self.samples_table)

            self.logger.debug("Metadata for %s stored on datastore" % sample_id)

        except DatastoreTemporaryException:
            raise
        except Exception as e:
            raise DatastoreStoreException(e)

    def track(self, sample_id, document):

        self.logger.debug("Storing tracking data for %s on datastore" % sample_id)

        option_lists = {}

        # Remove list entries from main document
        for key, values in document.items():
            if isinstance(values, (list, tuple)):
                option_lists[key] = values

        try:

            default_values = {
                "tags": [],
                "sources": [],
                "processors_dispatched": [],
                "processors_completed": [],
                "analyzers_dispatched": [],
                "analyzers_completed": [],
                "known_filenames": [],
                "parents": [],
            }

            document_body = {**default_values, **document}

            self._update(sample_id, document_body, table=self.tracking_table)

            self.logger.debug("Tracking data for %s stored on datastore" % sample_id)
            return True
        except DatastoreTemporaryException as e:
            raise e
        except Exception as e:
            raise DatastoreStoreException(e)

    def update_task_states(self):

        # @IMPLEMENTME add analysis_completed tag

        try:
            return True
        except DatastoreTemporaryException as e:
            raise e
        except Exception as e:
            raise DatastoreStoreException(e)

    def _search(self, body, index=None):

        return True

    def _update(self, sample_id, document_body, table):

        try:
            table.update(
                {'_id': sample_id},
                document_body,
                upsert = True
            )
        except Exception as e:
            raise DatastoreStoreException(e)
