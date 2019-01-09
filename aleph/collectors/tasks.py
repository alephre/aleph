import os
import json

from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.utils import load_collector, hash_data, encode_data

logger = get_task_logger(__name__)

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
