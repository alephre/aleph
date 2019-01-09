import os
import json

from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.utils import load_collector, hash_data, encode_data

logger = get_task_logger(__name__)

@app.task
def ingest():

    relay_folder = settings.get('relay_folder')

    logger.debug("Ingesting all samples from %s" % relay_folder)
    samples = [f for f in os.listdir(relay_folder) if os.path.isfile(os.path.join(relay_folder, f))]

    for s in samples:

        if not s.endswith(".sample"):
            continue

        path = os.path.join(relay_folder, s)
        logger.info("Ingesting sample %s" % path)

        # Get file contents
        with open(path, 'rb') as f:
            data = f.read()

        # Prepare sample (extract hash and convert data to serialization-safe)
        sample_id = hash_data(data)
        safe_data = encode_data(data)

        logger.debug("Retrieved %s data" % sample_id)

        # Get metadata
        metadata_path = os.path.join(relay_folder, "%s.json" % sample_id)
        with open(metadata_path, 'r') as f:
            metadata = json.loads(f.read())
        logger.debug("Retrieved %s metadata" % sample_id)

        # Store sample
        app.send_task('aleph.storages.tasks.store', args=[sample_id, safe_data])
        logger.debug("Sample %s sent to storage" % sample_id)

        # Create datastore entry
        app.send_task('aleph.datastores.tasks.store', args=[sample_id, metadata])
        logger.debug("Sample %s sent to datastore" % sample_id)

        # Prepare and send to processing pipeline
        sample = {
            'id': sample_id,
            'data': safe_data,
            'metadata': metadata,
        }
        app.send_task('aleph.tasks.process', args=[sample])
        logger.debug("Sample %s sent to processing pipeline" % sample_id)

        # Cleanup
        os.remove(path)
        os.remove(metadata_path)
        logger.debug("Sample %s cleaned up" % sample_id)

@app.task
def collect():

    collectors = settings.get('collectors')
    logger.debug("Found %d collectors: %s" % (len(collectors), ', '.join(collectors.keys())))
    for name, options in collectors.items():
        try:
            logger.debug("Loading %s collector" % name)
            collector = load_collector(name)(options)
            logger.debug("Running %s collector" % name)
            collector.collect()
            logger.debug("Collector %s completed" % name)
        except Exception as e:
            logger.error("Error running %s collector: %s" % (name, str(e)))
    logger.debug("Collection routine finished")
