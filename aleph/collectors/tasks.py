import os
import json

from aleph import app, settings
from aleph.loader import load_collector
from aleph.utils import hash_data, encode_data
from aleph.base import TaskBase

COLLECTORS = [(name, load_collector(name)(options)) for name, options in settings.get('collector').items()]

@app.task(bind=True, base=TaskBase)
def collect(self):

    for name, collector in COLLECTORS:
        self.logger.info("Running %s collector" % name)
        collector.collect()
        self.logger.debug("Collector %s completed" % name)

    self.logger.debug("Collection routine finished")
