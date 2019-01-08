from aleph import app, settings, logger
from aleph.utils import load_datastore

@app.task
def store(sample_id, metadata):

    datastores = settings.get('datastores')
    
    logger.debug("Found %d datastores: %s" % (len(datastores), ', '.join(datastores.keys())))

    for name, options in datastores.items():
        try:
            logger.debug("Loading datastore %s" % name)
            datastore = load_datastore(name)(options)
            logger.debug("Storing metadata for %s on datastore" % sample_id)
            datastore.store(sample_id, metadata)
            logger.debug("Metadata for %s stored on datastore" % sample_id)
        except Exception as e:
            logger.error("Error storing metadata for %s on datastore: %s" % (sample_id, str(e)))
        logger.debug("Datastore storage routine finished")
