#!/usr/bin/env python

import coloredlogs
import random
import logging
import sys

from celery import Celery
from celery.signals import setup_logging, celeryd_init, worker_ready, celeryd_after_setup #, after_setup_logger

from aleph.config import ConfigManager, routes, settings
from aleph.config.constants import CELERY_AUTODISCOVER_TASKS, ASCII_ART_ALEPH_LOGOS
from aleph.models import AlephTask

logger = logging.getLogger(__name__)

# Celery app creation
app = Celery('aleph')
app.Task = AlephTask

# Load Routes
app.config_from_object(routes)

# Celery Options
app.conf.update({
    'broker_url': settings.get('transport'),
    'result_backend': 'rpc://' if not settings.has_option('result_backend') else settings.get('result_backend'),
    'broker_transport_options': {'confirm_publish': True},
    'worker_hijack_root_logger': False,
    'event_timezone': 'UTC',
    'task_acks_late': True,
    'task_acks_on_failure_or_timeout': False,
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

@setup_logging.connect
def setup_loggers(*args, **kwargs):
#@after_setup_logger.connect
#def setup_loggers(logger, *args, **kwargs):

    root_logger = logging.getLogger()

    if not settings.has_option('logging'):
        return False

    log_options = settings.get('logging')
    version_info = settings.get('version')
    version = version_info['tag']

    if 'format' not in log_options:
        log_options['format'] = '%(asctime)s '+version+' %(name)s/%(funcName)s %(levelname)s: %(message)s'

    if 'level' not in log_options:
        log_options['level'] = 'WARNING'


    # Install colored console handler
    coloredlogs.install(level=log_options['level'], fmt=log_options['format'])

    # Add file handler if configured
    if 'path' in log_options:
        # FileHandler
        fh = logging.FileHandler(log_options['path'])
        formatter = logging.Formatter(log_options['format'])
        fh.setFormatter(formatter)
        root_logger.addHandler(fh)

    # Install filter on root logger handlers
    class AlephLogsFilter(logging.Filter):
        def filter(self, record):

            return record.name.startswith('aleph')

    for handler in root_logger.handlers:
        handler.addFilter(AlephLogsFilter())

    logger.debug('Logging setup successful.')


@celeryd_init.connect
def init_app(sender, instance, **kwargs):
    settings.set('worker_name', '{0}'.format(sender))
    with open('version.txt', 'r') as version:
        version_text = version.read().strip()
        version_parts = version_text.split(' ')
        version_info = {
            'branch': version_parts[0],
            'tag': version_parts[1],
            'rev': version_parts[2],
            'hash': version_parts[3]
        }
        settings.set('version', version_info)

@celeryd_after_setup.connect
def after_setup_cb(*args, **kwargs):
    version = settings.get('version')
    version_tag = f"{version['tag']}-r{version['rev']} ({version['hash']})"
    print(ASCII_ART_ALEPH_LOGOS % version_tag)
    logger.info("Aleph worker is initializing.")

@worker_ready.connect
def worker_ready_cb(*args, **kwargs):
    logger.info("Aleph worker is online.")

# Define global exception handler
def exception_handler(exception_type, exception, traceback, debug_hook=sys.excepthook):
    #if log_options['level'] is 'DEBUG':
    #    debug_hook(exception_type, exception, traceback)
    #else:
    logger.error("BAZINGA %s: %s" % (exception_type.__name__, exception))

sys.excepthook = exception_handler
