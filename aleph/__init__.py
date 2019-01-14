#!/usr/bin/env python

import logging

from celery import Celery
from celery.signals import after_setup_logger, celeryd_init

from aleph import routes
from aleph.config import ConfigManager

# Celery app creation
app = Celery('aleph')

# Setup Aleph Settings
settings = ConfigManager()
settings.load('config.yaml')

# Load Config
app.config_from_object(routes)

app.conf.update({
    'broker_url': settings.get('transport'),
    'broker_transport_options': {'confirm_publish': True},
    'event_timezone': 'UTC',
    'task_acks_late': True,
    'task_reject_on_worker_lost': True,
    'task_annotations': {
        '*': {
            'max_retries': None,
            'retry_backoff': True,
            'default_retry_delay': 10,
            }
        },
    })

# Autodiscover tasks
app.autodiscover_tasks([
    'aleph',
    'aleph.collectors',
    'aleph.processors',
    'aleph.analyzers',
    'aleph.datastores',
    'aleph.storages',
])

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
