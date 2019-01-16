from aleph import app
from aleph.common.utils import run_plugin

@app.task(bind=True)
def run(self, processor_name, sample):

    self.logger.info('Applying processor %s on sample %s' % (processor_name, sample['id']))
    run_plugin('processor', processor_name, sample)
