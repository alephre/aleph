import os

from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.utils import load_storage

logger = get_task_logger(__name__)

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
            raise self.retry(exc=e)

    logger.debug("Storage routine finished")
