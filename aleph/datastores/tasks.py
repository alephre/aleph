from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.loader import load_datastore

logger = get_task_logger(__name__)

DATASTORES = [(name, load_datastore(name)(options)) for name, options in settings.get('datastore').items()]

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def update_task_states():

    for name, datastore in DATASTORES:
        logger.debug("Calling 'update_task_states' on %s datastore" % name)
        datastore.update_task_states()

    logger.debug("'update_task_states' completed on all datastores")

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def store(sample_id, metadata):

    for name, datastore in DATASTORES:
        logger.debug("Storing metadata for %s on datastore" % sample_id)
        datastore.store(sample_id, metadata)
        logger.debug("Metadata for %s stored on datastore" % sample_id)

    logger.debug("Datastore storage routine finished")
