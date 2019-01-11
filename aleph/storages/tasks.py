import os

from aleph import app, settings
from aleph.loader import load_storage
from aleph.base import TaskBase

STORAGES = [(name, load_storage(name)(options)) for name, options in settings.get('storage').items()]

@app.task(bind=True, base=TaskBase)
def store(self, sample_id, sample_data, enqueue=True):

    for name, storage in STORAGES:
        self.logger.info("Storing %s to %s storage" % (sample_id, name))
        storage.store(sample_id, sample_data)
        self.logger.debug("Sample %s stored to %s storage" % (sample_id, name))

    self.logger.debug("Storage routine finished")
