#!/usr/bin/env python

import logging

from celery import Celery
from celery.signals import after_setup_logger, celeryd_init

from aleph.config import ConfigManager, routes, settings
from aleph.config.constants import CELERY_AUTODISCOVER_TASKS
from aleph.common.base import TaskBase

# Celery app creation
app = Celery('aleph')
app.Task = TaskBase

# Load Routes
app.config_from_object(routes)

# Celery Options
app.conf.update({
    'broker_url': settings.get('transport'),
    'result_backend': 'rpc://' if not settings.has_option('result_backend') else settings.get('result_backend'),
    'broker_transport_options': {'confirm_publish': True},
    'event_timezone': 'UTC',
    'task_acks_late': True,
    'task_reject_on_worker_lost': True,
    'task_annotations': {
        '*': {
            'max_retries': None if not settings.has_option('max_retries') else settings.get('max_retries'),
            'retry_backoff': True,
            'default_retry_delay': 10 if not settings.has_option('default_retry_delay') else settings.get('default_retry_delay'),
            }
        },
    })



# Autodiscover tasks
app.autodiscover_tasks(CELERY_AUTODISCOVER_TASKS, force=True)

@after_setup_logger.connect
def setup_loggers(logger, *args, **kwargs):

    if not settings.has_option('logging'):
        return False

    log_options = settings.get('logging')
    version = settings.get('version')

    if 'format' not in log_options:
        log_options['format'] = '%(asctime)s '+version+' %(name)s %(funcName)10s() %(levelname)s: %(message)s'

    formatter = logging.Formatter(log_options['format'])

    if 'path' in log_options:
        # FileHandler
        fh = logging.FileHandler(log_options['path'])
        fh.setFormatter(formatter)
        logger.addHandler(fh)

@celeryd_init.connect
def init_app(sender, instance, **kwargs):
    settings.set('worker_name', '{0}'.format(sender))
    with open('version.txt', 'r') as version:
        settings.set('version', version.read().strip())
