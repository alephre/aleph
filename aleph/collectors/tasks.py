import os
import json

from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.loader import load_collector
from aleph.utils import hash_data, encode_data

logger = get_task_logger(__name__)

COLLECTORS = [(name, load_collector(name)(options)) for name, options in settings.get('collectors').items()]

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def collect():

    for name, collector in COLLECTORS:
        logger.debug("Running %s collector" % name)
        collector.collect()
        logger.debug("Collector %s completed" % name)

    logger.debug("Collection routine finished")
