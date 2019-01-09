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
        try:
            self.logger.debug("Retrieving metadata for %s" % sample_id)
            #@IMPLEMENTME @jseidl need to do a search for matching hash
            self.logger.debug("Metadata retrieved for %s" % sample_id)
        except Exception as e:
            self.logger.error("Error retrieving sample %s: %s" % (sample_id, str(e)))

    def store(self, sample_id, document):
        try:
            self.logger.debug("Storing sample %s on datastore" % sample_id)
            self.engine.update(
                id=sample_id,
                index=self.options.get('index'), 
                doc_type=self.options.get('doctype'),
                body={'doc': document, 'doc_as_upsert': True}
                )
            self.logger.debug("Sample %s stored on datastore" % sample_id)
            return True
        except Exception as e:
            self.logger.error("Failed sending %s to datastore: %s" % (sample_id, str(e)))
            return False

