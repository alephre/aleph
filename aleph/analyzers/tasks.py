from aleph import app
from aleph.utils import run_plugin
from aleph.base import TaskBase


@app.task(bind=True, base=TaskBase)
def run(self, analyzer_name, sample):

    self.logger.info('Applying analyzer %s on sample %s' % (analyzer_name, sample['id']))
    run_plugin('analyzer', analyzer_name, sample)
