from elasticsearch import Elasticsearch
from aleph.base import DatastoreBase

class ElasticsearchDatastore(DatastoreBase):

    default_options = {
        'host': 'localhost',
        'port': 9200,
        'index': 'aleph',
        'doctype': 'sample',
    }

    def setup(self):
        self.logger.debug("Connecting to elasticsearch at %s:%d" % (self.options.get('host'), self.options.get('port')))
        self.engine = Elasticsearch([{
            'host': self.options.get('host'),
            'port': self.options.get('port'),
        }])

        if not self.engine.ping():
            self.logger.error("Error connecting to elasticsearch at %s:%d" % (self.options.get('host'), self.options.get('port')))
        self.logger.debug("Connected to elasticsearch")

    def retrieve(self, sample_id):
        self.logger.debug("Retrieving metadata for %s" % sample_id)
        result = self.engine.get(index=self.options.get('index'), doc_type=self.options.get('doctype'), id=sample_id)['_source']
        self.logger.debug("Metadata retrieved for %s" % sample_id)
        return result

    def store(self, sample_id, document):

        self.logger.debug("Storing sample %s on datastore" % sample_id)

        option_lists = {}
        treated_document = {}

        # Remove list entries from main document
        for key, values in document.items():
            if key is 'artifacts':
                continue
            if type(values) in [list, tuple]:
                option_lists[key] = document[key]
            else:
                treated_document[key] = document[key]

        document_body = {
            'doc': treated_document,
            'upsert': {
                'tags': [],
                'sources': [],
                'plugins_dispatched': [],
                'plugins_completed': [],
                }
            }

        self._update(sample_id, document_body)

        # Add list elements one by one
        for key, values in option_lists.items():
            self._update_array(sample_id, key, values)

        self.logger.debug("Metadata for %s stored on datastore" % sample_id)

    def update_task_states(self):

        body = {
            "query": {
                "bool" : {
                    "filter" : [
                        {"script" : {"script" : {"source": "doc['plugins_completed'].containsAll(doc['plugins_dispatched'])", "lang": "painless"}}},
                        {"script" : {"script" : {"source": "!doc['tags'].contains('scan_completed')", "lang": "painless"}}}
                    ]
                }
            },
            "stored_fields": []
        }

        result = self._search(body)['hits']

        if not result['total']:
            self.logger.debug('No untagged complete tasks')
            return True
            
        for entry in result['hits']:
            sample_id = entry['_id'] 
            self.logger.debug("Tagging sample %s as 'scan_completed'" % sample_id)
            self._update_array(sample_id, 'tags', ['scan_completed'])

    def _search(self, body):

        result = self.engine.search(
            index=self.options.get('index'),
            doc_type=self.options.get('doctype'), body=body
            )

        return result

    def _update_array(self, sample_id, array_name, values):

            params = {}
            params[array_name] = values

            document_body = {
                "scripted_upsert": True,
                "script": {
                    "source": "ctx._source.%s.addAll(params.%s)" % (array_name, array_name),
                    "lang": "painless",
                    "params": params
                },
            }

            self._update(sample_id, document_body)

    def _update(self, sample_id, document_body):

        self.engine.update(
            id=sample_id,
            index=self.options.get('index'), 
            doc_type=self.options.get('doctype'),
            body=document_body
            )
