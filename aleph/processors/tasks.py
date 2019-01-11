from aleph import app
from aleph.utils import run_plugin
from aleph.base import TaskBase

@app.task(bind=True, base=TaskBase)
def run(self, processor_name, sample):

    self.logger.info('Applying processor %s on sample %s' % (processor_name, sample['id']))
    run_plugin('processor', processor_name, sample)
