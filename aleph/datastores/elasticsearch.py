import logging 

from elasticsearch import Elasticsearch as ES
from elasticsearch.exceptions import ConflictError, ConnectionTimeout
from urllib3.exceptions import ReadTimeoutError

from aleph.config.constants import FIELD_SAMPLE_PROCESSOR_ITEMS, FIELD_SAMPLE_ANALYZER_ITEMS, FIELD_SAMPLE_SIZE, FIELD_SAMPLE_FILETYPE, FIELD_SAMPLE_FILETYPE_DESC, FIELD_SAMPLE_TIMESTAMP, FIELD_SAMPLE_IOCS
from aleph.exceptions import DatastoreTemporaryException, DatastoreSearchException, DatastoreStoreException, DatastoreRetrieveException
from aleph.models import Datastore
from aleph.helpers.iocs import default_values as ioc_default_values

DEFAULT_TIMEOUT=30

class Elasticsearch(Datastore):

    default_options = {
        'host': 'localhost',
        'port': 9200,
        'index': 'aleph-samples',
        'tracking_index': 'aleph-tracking',
        'doctype': 'sample',
    }

    def setup(self):
        try:
            self.logger.debug("Connecting to elasticsearch at %s:%d" % (self.options.get('host'), self.options.get('port')))
            self.engine = ES([{
                'host': self.options.get('host'),
                'port': self.options.get('port'),
            }])

            if not self.engine.ping():
                self.logger.error("Error connecting to elasticsearch at %s:%d" % (self.options.get('host'), self.options.get('port')))
            self.logger.debug("Connected to elasticsearch")

            # Disable elasticsearch logging @FIXME maybe a mistake
            es_logger = logging.getLogger('elasticsearch')
            es_logger.propagate = False
            es_trace_logger = logging.getLogger('elasticsearch')
            es_trace_logger.propagate = False
        except Exception as e:
            self.logger.error('Error setting up Elasticsearch datastore: %s' % str(e))

    def _get(self, sample_id, index=None):

        try:
            if not index:
                index = self.options.get('index')

            return self.engine.get(index=index, doc_type=self.options.get('doctype'), id=sample_id)
        except (ReadTimeoutError, ConnectionTimeout) as e:
            raise DatastoreTemporaryException(e)
        except Exception as e:
            raise DatastoreRetrieveException(e)

    def retrieve(self, sample_id):

        try:
            self.logger.debug("Retrieving metadata for %s" % sample_id)
            result = self._get(sample_id)
            self.logger.debug("Metadata retrieved for %s" % sample_id)
            if result and 'found' in result.keys() and result['found']:
                return result['_source']
            return None
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

            upsert = {**default_values, **document}

            document_body = {
                'doc': document,
                'upsert': upsert,
                }

            self._update(sample_id, document_body)

            self.logger.debug("Metadata for %s stored on datastore" % sample_id)

        except DatastoreTemporaryException as e:
            raise
        except Exception as e:
            raise DatastoreStoreException(e)


    def track(self, sample_id, document):

        self.logger.debug("Storing tracking data for %s on datastore" % sample_id)

        track_index = self.options.get('tracking_index')

        option_lists = {}
        treated_document = {}

        # Remove list entries from main document
        for key, values in document.items():
            if type(values) in [list, tuple]:
                option_lists[key] = document[key]
            else:
                treated_document[key] = document[key]

        try:

            default_values = {
                'tags': [],
                'sources': [],
                'processors_dispatched': [],
                'processors_completed': [],
                'analyzers_dispatched': [],
                'analyzers_completed': [],
                'known_filenames': [],
                'parents': [],
            }

            # Merge document with defaults for upsert case
            upsert = {**default_values, **treated_document}

            document_body = {
                'doc': treated_document,
                'upsert': upsert,
                }

            self._update(sample_id, document_body, index=track_index)

            # Add list elements one by one
            for key, values in option_lists.items():
                if len(values) == 0:
                    continue
                self._update_array(sample_id, key, values, index=track_index)

            self.logger.debug("Tracking data for %s stored on datastore" % sample_id)
            return True
        except DatastoreTemporaryException as e:
            raise
        except Exception as e:
            raise DatastoreStoreException(e)

    def update_task_states(self):

        track_index = self.options.get('tracking_index')

        body = {
            "query": {
                "bool" : {
                    "filter" : [
                        {"script" : {"script" : {"source": "doc['processors_completed'].containsAll(doc['processors_dispatched'])", "lang": "painless"}}},
                        {"script" : {"script" : {"source": "!doc['tags'].contains('scan_completed')", "lang": "painless"}}}
                    ]
                }
            },
            "stored_fields": []
        }

        try:
            search_obj = self._search(body, index=track_index)

            if not search_obj or not isinstance(search_obj, dict) or 'hits' not in search_obj.keys():
                self.logger.debug('Invalid search body received')
                return False

            result = search_obj['hits']

            if not result['total']:
                self.logger.debug('No untagged complete tasks')
                return True
                
            for entry in result['hits']:
                sample_id = entry['_id'] 
                sample_data = self.retrieve(sample_id)
                if not sample_data:
                    self.logger.warn('No sample data for sample %s. Skipping' % sample_id)
                    continue
                self.dispatch(sample_id, sample_data)
                self.logger.debug("Tagging sample %s as 'scan_completed'" % sample_id)
                self._update_array(sample_id, 'tags', ['scan_completed'], index=track_index)

            return True
        except DatastoreTemporaryException as e:
            raise e
        except Exception as e:
            raise DatastoreStoreException(e)

    def _search(self, body, index=None):

        if not index:
            index = self.options.get('indexs')

        try:
            result = self.engine.search(
                index=index,
                doc_type=self.options.get('doctype'), body=body
                )

            return result
        except (ReadTimeoutError, ConnectionTimeout) as e:
            raise DatastoreTemporaryException(e)
        except Exception as e:
            raise DatastoreSearchException(e)

    def _update_array(self, sample_id, array_name, values, index=None):

            statements = []
            params_object = {}

            for i, value in enumerate(values):

                value_key = 'value_%d' % i
                params_object[value_key] = value
                
                statements.append(f"if (ctx._source.{array_name}.contains(params.{value_key})) {{ ctx.op = 'none' }} else {{ ctx._source.{array_name}.add(params.{value_key}) }}")

            try:

                document_body = {
                    "scripted_upsert": True,
                    "script": {
                        "source": "\n".join(statements).lower(),
                        "lang": "painless",
                        "params": params_object
                    },
                }

                self._update(sample_id, document_body, index=index)
            except (DatastoreTemporaryException, DatastoreStoreException) as e:
                raise e
            except Exception as e:
                raise DatastoreStoreException(e)

            return True

    def _update(self, sample_id, document_body, index=None):

        if not index:
            index = self.options.get('index')

        try:
            self.engine.update(
                id=sample_id,
                index=index, 
                doc_type=self.options.get('doctype'),
                body=document_body,
                request_timeout=DEFAULT_TIMEOUT
                )
        except ConflictError as e:
            raise DatastoreTemporaryException('Update conflict, possibly due concurrency.')
        except Exception as e:
            raise DatastoreStoreException(e)
