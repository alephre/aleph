#!/usr/bin/env python

import logging

from celery import Celery
from celery.signals import after_setup_logger, celeryd_after_setup

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
    })

# Autodiscover tasks
app.autodiscover_tasks([
    'aleph',
    'aleph.collectors',
    'aleph.plugins',
    'aleph.datastores',
    'aleph.storages',
])

@after_setup_logger.connect
def setup_loggers(logger, *args, **kwargs):

    if not settings.has_option('logging'):
        return False

    log_options = settings.get('logging')

    if 'format' not in log_options:
        log_options['format'] = '%(asctime)s %(name)s %(funcName)10s() %(levelname)s: %(message)s'

    formatter = logging.Formatter(log_options['format'])

    if 'path' in log_options:
        # FileHandler
        fh = logging.FileHandler(log_options['path'])
        fh.setFormatter(formatter)
        logger.addHandler(fh)

@celeryd_after_setup.connect
def capture_worker_name(sender, instance, **kwargs):
    settings.set('worker_name', '{0}'.format(sender))
