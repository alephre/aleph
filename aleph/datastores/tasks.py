from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.utils import load_datastore

logger = get_task_logger(__name__)

@app.task
def store(sample_id, metadata):

    datastores = settings.get('datastores')
    
    logger.debug("Found %d datastores: %s" % (len(datastores), ', '.join(datastores.keys())))

    try:

        for name, options in datastores.items():
            logger.debug("Loading datastore %s" % name)
            datastore = load_datastore(name)(options)
            logger.debug("Storing metadata for %s on datastore" % sample_id)
            datastore.store(sample_id, metadata)
            logger.debug("Metadata for %s stored on datastore" % sample_id)

    except Exception as e:
        logger.error('Error sending %s metadata to datastores: %s' % (sample_id, str(e)))
        self.retry(exc=e)

    logger.debug("Datastore storage routine finished")
