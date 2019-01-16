from aleph import app
from aleph.config import settings
from aleph.common.loader import load_collector

COLLECTORS = [(name, load_collector(name)(options)) for name, options in settings.get('collector').items()] if settings.has_option('collector') else []

@app.task(bind=True)
def collect(self):

    for name, collector in COLLECTORS:
        self.logger.info("Running %s collector" % name)
        collector.collect()
        self.logger.debug("Collector %s completed" % name)

    self.logger.debug("Collection routine finished")
