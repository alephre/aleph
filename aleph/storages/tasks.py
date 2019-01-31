import os

from aleph import app
from aleph.config import settings
from aleph.common.loader import load_storage
from aleph.common.utils import encode_data, decode_data

STORAGES = [(name, load_storage(name)(options)) for name, options in settings.get('storage').items()]

@app.task(bind=True)
def store(self, sample_id, sample_data, enqueue=True):

    for name, storage in STORAGES:
        self.logger.info("Storing %s to %s storage" % (sample_id, name))
        storage.store(sample_id, decode_data(sample_data))
        self.logger.debug("Sample %s stored to %s storage" % (sample_id, name))

@app.task(bind=True)
def retrieve(self, sample_id):

    for name, storage in STORAGES:
        self.logger.info("Retrieving %s from %s storage" % (sample_id, name))
        sample = storage.retrieve(sample_id)
        if sample:
            break
        self.logger.debug("Sample %s retrieved from %s storage" % (sample_id, name))

    return encode_data(sample)
