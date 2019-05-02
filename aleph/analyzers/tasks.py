from aleph import app
from aleph.helpers.plugins import run_plugin

@app.task(bind=True)
def run(self, analyzer_name, sample):

    self.logger.info('Applying analyzer %s on sample %s' % (analyzer_name, sample['id']))
    run_plugin('analyzer', analyzer_name, sample)
