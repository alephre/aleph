import logging
import socket

from elasticsearch import Elasticsearch as ES
from elasticsearch.exceptions import ConflictError, ConnectionTimeout
from urllib3.exceptions import ReadTimeoutError, ProtocolError
from slugify import slugify

from aleph.config.constants import (
    FIELD_SAMPLE_PROCESSOR_ITEMS,
    FIELD_SAMPLE_ANALYZER_ITEMS,
    FIELD_SAMPLE_SIZE,
    FIELD_SAMPLE_FILETYPE,
    FIELD_SAMPLE_FILETYPE_DESC,
    FIELD_SAMPLE_TIMESTAMP,
    FIELD_SAMPLE_IOCS,
)
from aleph.exceptions import (
    DatastoreTemporaryException,
    DatastoreSearchException,
    DatastoreStoreException,
    DatastoreRetrieveException,
)
from aleph.models import Datastore
from aleph.helpers.iocs import default_values as ioc_default_values

MAX_SCRIPT_LEN = 10000


class Elasticsearch(Datastore):

    default_options = {
        "host": "localhost",
        "port": 9200,
        "index": "aleph-samples",
        "tracking_index": "aleph-tracking",
        "doctype": "sample",
        "connection_timeout": 10.0,
    }

    def setup(self):
        try:
            self.logger.debug(
                "Connecting to elasticsearch at %s:%d"
                % (self.options.get("host"), self.options.get("port"))
            )

            self.engine = ES(
                [{"host": self.options.get("host"), "port": self.options.get("port")}],
                # sniff_on_start=True,
                # sniff_on_connection_fail=True,
                # sniffer_timeout=60,
                timeout=self.options.get("connection_timeout"),
            )

            if not self.engine.ping():
                self.logger.error(
                    "Error connecting to elasticsearch at %s:%d"
                    % (self.options.get("host"), self.options.get("port"))
                )
            self.logger.debug("Connected to elasticsearch")

            # Disable elasticsearch logging @FIXME maybe a mistake
            disable_loggers = ["elasticsearch", "elasticsearch.trace", "urllib3"]
            for dl in disable_loggers:
                dl_obj = logging.getLogger(dl)
                dl_obj.propagate = False
                dl_obj.setLevel(logging.CRITICAL)

        except Exception as e:
            self.logger.error("Error setting up Elasticsearch datastore: %s" % str(e))

    def _get(self, sample_id, index=None):

        try:
            if not index:
                index = self.options.get("index")

            return self.engine.get(
                index=index,
                doc_type=self.options.get("doctype"),
                request_timeout=self.options.get("connection_timeout"),
                id=sample_id,
            )
        except (
            ProtocolError,
            ReadTimeoutError,
            ConnectionTimeout,
            socket.timeout,
        ) as e:
            raise DatastoreTemporaryException(e)
        except Exception as e:
            raise DatastoreRetrieveException(e)

    def retrieve(self, sample_id):

        try:
            self.logger.debug("Retrieving metadata for %s" % sample_id)
            result = self._get(sample_id)
            self.logger.debug("Metadata retrieved for %s" % sample_id)
            if result and "found" in result.keys() and result["found"]:
                return result["_source"]
            return None
        except (DatastoreTemporaryException, DatastoreRetrieveException) as e:
            raise e
        except Exception as e:
            raise DatastoreRetrieveException(e)

    def store(self, sample_id, document):

        self.logger.debug("Storing sample %s on datastore" % sample_id)

        try:

            iocs = {}
            default_values = {
                FIELD_SAMPLE_TIMESTAMP: None,
                FIELD_SAMPLE_SIZE: 0,
                FIELD_SAMPLE_FILETYPE: None,
                FIELD_SAMPLE_FILETYPE_DESC: None,
                FIELD_SAMPLE_PROCESSOR_ITEMS: {},
                FIELD_SAMPLE_ANALYZER_ITEMS: {},
                FIELD_SAMPLE_IOCS: ioc_default_values,
            }

            if FIELD_SAMPLE_IOCS in document.keys():
                iocs = document.pop(FIELD_SAMPLE_IOCS)

            upsert = {**default_values, **document}

            document_body = {"doc": document, "upsert": upsert}

            self._update(sample_id, document_body)

            # Extract iocs
            option_list = {}
            for ioc_type, ioc_values in iocs.items():
                list_key = f"iocs.{ioc_type}"
                option_list[list_key] = ioc_values

            if option_list:
                self._update_array(sample_id, option_list)

            self.logger.debug("Metadata for %s stored on datastore" % sample_id)

        except DatastoreTemporaryException:
            raise
        except Exception as e:
            raise DatastoreStoreException(e)

    def track(self, sample_id, document):

        self.logger.debug("Storing tracking data for %s on datastore" % sample_id)

        track_index = self.options.get("tracking_index")

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

            document_body = {"doc": {}, "upsert": default_values}

            self._update(sample_id, document_body, index=track_index)

            if option_lists:
                self._update_array(sample_id, option_lists, index=track_index)

            self.logger.debug("Tracking data for %s stored on datastore" % sample_id)
            return True
        except DatastoreTemporaryException as e:
            raise e
        except Exception as e:
            raise DatastoreStoreException(e)

    def update_task_states(self):

        # @IMPLEMENTME add analysis_completed tag

        track_index = self.options.get("tracking_index")

        body = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "script": {
                                "script": {
                                    "source": "doc['processors_completed'].containsAll(doc['processors_dispatched'])",
                                    "lang": "painless",
                                }
                            }
                        },
                        {
                            "script": {
                                "script": {
                                    "source": "!doc['tags'].contains('processing_completed')",
                                    "lang": "painless",
                                }
                            }
                        },
                    ]
                }
            },
            "stored_fields": [],
        }

        try:
            search_obj = self._search(body, index=track_index)

            if (
                not search_obj
                or not isinstance(search_obj, dict)
                or "hits" not in search_obj.keys()
            ):
                self.logger.debug("Invalid search body received")
                return False

            result = search_obj["hits"]

            if not result["total"]:
                self.logger.debug("No untagged complete tasks")
                return True

            for entry in result["hits"]:

                sample_id = entry["_id"]
                sample_data = self.retrieve(sample_id)

                if not sample_data:
                    self.logger.warn("Sample %s is not ready yet. Skipping" % sample_id)
                    continue

                # Dispatch for analysis
                self.dispatch(sample_id, sample_data)

                # Track processing complete
                self.logger.info("Processing complete for %s" % sample_id)
                option_list = {"tags": ["processing_completed"]}
                self.track(sample_id, option_list)

            return True
        except DatastoreTemporaryException as e:
            raise e
        except Exception as e:
            raise DatastoreStoreException(e)

    def _search(self, body, index=None):

        if not index:
            index = self.options.get("index")

        try:
            result = self.engine.search(
                index=index,
                doc_type=self.options.get("doctype"),
                body=body,
                request_timeout=self.options.get("connection_timeout"),
            )

            return result
        except (ProtocolError, ReadTimeoutError, ConnectionTimeout, socket.timeout):
            raise DatastoreTemporaryException("Timeout searching backend.")
        except Exception as e:
            raise DatastoreSearchException(e)

    def _create_update_statements(self, key, values):

        statements = []
        params_object = {}

        for i, value in enumerate(values):

            value_key = f"value_{key}_{i}"
            safe_key = slugify(value_key, separator="_")
            params_object[safe_key] = value

            script_str = f"if (!ctx._source.{key}.contains(params.{safe_key})) {{ ctx._source.{key}.add(params.{safe_key}) }}"
            statements.append(script_str)

        return statements, params_object

    def _update_array(self, sample_id, option_lists, index=None):

        if not option_lists:
            self.logger.debug("Received empty option list to update. Skipping")
            return False

        if not index:
            index = self.options.get("index")

        statements = []
        params = {}

        for key, values in option_lists.items():
            if len(values) == 0:
                continue
            _st, _p = self._create_update_statements(key, values)
            statements += _st
            params.update(_p)

        if not statements:
            self.logger.debug("Option list contained only empty values, skipping.")
            return False

        # Check if script size is gonna blow ES script size limit
        total_size = sum([len(i) for i in statements])

        statement_blocks = []
        block_entries = []
        block_size = 0

        if total_size > MAX_SCRIPT_LEN:

            for s in statements:
                st_size = len(s)
                if (block_size + st_size) < MAX_SCRIPT_LEN:
                    block_entries.append(s)
                    block_size += st_size
                else:
                    statement_blocks.append(block_entries)
                    block_entries = [s]
                    block_size = st_size

            statement_blocks.append(block_entries)
        else:
            statement_blocks.append(statements)

        try:

            for stmts in statement_blocks:

                statement_body = "\n".join(stmts).lower()

                document_body = {
                    # "scripted_upsert": True,
                    "script": {
                        "source": statement_body,
                        "lang": "painless",
                        "params": params,
                    }
                }

                self._update(sample_id, document_body, index=index)
        except (DatastoreTemporaryException, DatastoreStoreException) as e:
            raise e
        except Exception as e:
            raise DatastoreStoreException(e)

        return True

    def _update(self, sample_id, document_body, index=None):

        if not index:
            index = self.options.get("index")

        try:
            self.engine.update(
                id=sample_id,
                index=index,
                doc_type=self.options.get("doctype"),
                body=document_body,
                request_timeout=self.options.get("connection_timeout"),
            )
        except (ProtocolError, ReadTimeoutError, ConnectionTimeout, socket.timeout):
            raise DatastoreTemporaryException("Backend timeout.")
        except ConflictError:
            raise DatastoreTemporaryException(
                "Update conflict, possibly due concurrency."
            )
        except Exception as e:
            """
            self.logger.error("--- MARK ----")
            self.logger.error(document_body)
            """
            raise DatastoreStoreException(e)
