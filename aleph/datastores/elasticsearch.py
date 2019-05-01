import logging 

from elasticsearch import Elasticsearch as ES
from elasticsearch.exceptions import ConflictError, ConnectionTimeout

from aleph.common.exceptions import DatastoreTemporaryException, DatastoreSearchException, DatastoreStoreException, DatastoreRetrieveException
from aleph.common.base import Datastore

DEFAULT_TIMEOUT=30

class Elasticsearch(Datastore):

    default_options = {
        'host': 'localhost',
        'port': 9200,
        'index': 'aleph',
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

    def retrieve(self, sample_id):

        try:
            self.logger.debug("Retrieving metadata for %s" % sample_id)
            result = self.engine.get(index=self.options.get('index'), doc_type=self.options.get('doctype'), id=sample_id)
            self.logger.debug("Metadata retrieved for %s" % sample_id)
            if result and 'found' in result.keys() and result['found']:
                return result['_source']
            return None
        except ConnectionTimeout as e:
            raise DatastoreTemporaryException(e)
        except Exception as e:
            raise DatastoreRetrieveException(e)

    def store(self, sample_id, document):

        self.logger.debug("Storing sample %s on datastore" % sample_id)

        option_lists = {}
        treated_document = {}

        # Remove list entries from main document
        for key, values in document.items():
            if type(values) in [list, tuple] and key not in ['artifacts','flags']:
                option_lists[key] = document[key]
            else:
                treated_document[key] = document[key]

        default_arrays = {
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
        upsert = {**default_arrays, **treated_document}

        try:
            document_body = {
                'doc': treated_document,
                'upsert': upsert,
                }

            self._update(sample_id, document_body)

            # Add list elements one by one
            for key, values in option_lists.items():
                if len(values) == 0:
                    continue
                self._update_array(sample_id, key, values)

            self.logger.debug("Metadata for %s stored on datastore" % sample_id)
            return True
        except DatastoreTemporaryException as e:
            raise
        except Exception as e:
            raise DatastoreStoreException(e)

    def update_task_states(self):

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
            search_obj = self._search(body)

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
                self._update_array(sample_id, 'tags', ['scan_completed'])

            return True
        except DatastoreTemporaryException as e:
            raise e
        except Exception as e:
            raise DatastoreStoreException(e)

    def _search(self, body):

        try:
            result = self.engine.search(
                index=self.options.get('index'),
                doc_type=self.options.get('doctype'), body=body
                )

            return result
        except ConnectionTimeout as e:
            raise DatastoreTemporaryException(e)
        except Exception as e:
            raise DatastoreSearchException(e)

    def _update_array(self, sample_id, array_name, values):

            #params = {}
            #params[array_name] = values

            statements = []
            params_object = {}

            for index, value in enumerate(values):

                value_key = 'value_%d' % index
                params_object[value_key] = value
                
                statements.append(f"if (ctx._source.{array_name}.contains(params.{value_key})) {{ ctx.op = 'none' }} else {{ ctx._source.{array_name}.add(params.{value_key}) }}")

            try:

                document_body = {
                    "scripted_upsert": True,
                    "script": {
                        #"source": "ctx._source.%s.addAll(params.%s)" % (array_name, array_name),
                        "source": "\n".join(statements).lower(),
                        "lang": "painless",
                        "params": params_object
                    },
                }

                self._update(sample_id, document_body)
            except DatastoreTemporaryException as e:
                raise e
            except Exception as e:
                raise DatastoreStoreException(e)

            return True

    def _update(self, sample_id, document_body):

        try:
            self.engine.update(
                id=sample_id,
                index=self.options.get('index'), 
                doc_type=self.options.get('doctype'),
                body=document_body,
                request_timeout=DEFAULT_TIMEOUT
                )
        except ConflictError as e:
            raise DatastoreTemporaryException('Update conflict, possibly due concurrency.')
        except Exception as e:
            raise DatastoreStoreException(e)
