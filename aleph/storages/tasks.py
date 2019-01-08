import os

from aleph import app, logger, settings
from aleph.utils import load_storage

@app.task
def store(sample_id, sample_data, enqueue=True):

    storages = settings.get('storages')
    logger.debug("Found %d storages: %s" % (len(storages), ', '.join(storages.keys())))

    for name, options in storages.items():
        try:
            logger.debug("Loading storage handler %s" % name)
            storage = load_storage(name)(options)
            logger.debug("Storing %s to %s storage" % (sample_id, name))
            storage.store(sample_id, sample_data)
            logger.debug("Sample %s stored to %s storage" % (sample_id, name))
        except Exception as e:
            logger.error("Error storing %s to %s storage" % (sample_id, name))
    logger.debug("Storage routine finished")
