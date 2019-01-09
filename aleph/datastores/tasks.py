from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.utils import load_datastore

logger = get_task_logger(__name__)

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def store(sample_id, metadata):

    datastores = settings.get('datastores')
    
    logger.debug("Found %d datastores: %s" % (len(datastores), ', '.join(datastores.keys())))

    for name, options in datastores.items():
        logger.debug("Loading datastore %s" % name)
        datastore = load_datastore(name)(options)
        logger.debug("Storing metadata for %s on datastore" % sample_id)
        datastore.store(sample_id, metadata)
        logger.debug("Metadata for %s stored on datastore" % sample_id)

    logger.debug("Datastore storage routine finished")
