#!/usr/bin/env python

import logging

from celery import Celery
from celery.signals import after_setup_logger

from aleph import routes
from aleph.constants import DEFAULT_OPTIONS
from aleph.utils import ConfigManager

# Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Celery app creation
app = Celery('aleph')

# Setup Aleph Settings
settings = ConfigManager()
settings.load('config.yaml')

# Load Config
app.config_from_object(routes)
app.conf.timezone = settings.get('event_timezone')
app.conf.broker_url = settings.get('transport')
# Broker persistance
app.conf.broker_transport_options = {'confirm_publish': True}
app.conf.task_acks_late = True
app.conf.task_reject_on_worker_lost = True

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
    formatter = logging.Formatter('%(asctime)s %(name)s %(funcName)10s() %(levelname)s: %(message)s')

    # FileHandler
    fh = logging.FileHandler('logs.log')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
