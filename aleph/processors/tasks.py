from celery.utils.log import get_task_logger

from aleph import app
from aleph.utils import run_plugin

logger = get_task_logger(__name__)

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def run(processor_name, sample):

    run_plugin('processor', processor_name, sample)
