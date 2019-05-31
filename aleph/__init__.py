# -*- coding: utf-8 -*-
"""Main package __init__.

This module sets up the celery configuration and creates the app.
Celery signals are trapped for logging setup and indicate that the
worker is up and ready to go.
"""

import logging
import coloredlogs

from celery import Celery
from celery.signals import (
    setup_logging,
    celeryd_init,
    worker_ready,
    celeryd_after_setup,
)

from aleph.config import routes, settings
from aleph.models import AlephTask
from aleph.config.constants import CELERY_AUTODISCOVER_TASKS, ASCII_ART_ALEPH_LOGO

LOGGER = logging.getLogger(__name__)

# Celery app creation
app = Celery("aleph")
app.Task = AlephTask

# Load Routes
app.config_from_object(routes)

# Celery Options
RESULT_BACKEND = (
    "rpc://"
    if not settings.has_option("result_backend")
    else settings.get("result_backend")
)

DEFAULT_RETRY_DELAY = (
    10
    if not settings.has_option("default_retry_delay")
    else settings.get("default_retry_delay")
)

MAX_RETRIES = (
    None if not settings.has_option("max_retries") else settings.get("max_retries")
)

app.conf.update(
    {
        "broker_url": settings.get("transport"),
        "result_backend": RESULT_BACKEND,
        "broker_transport_options": {"confirm_publish": True},
        "worker_hijack_root_logger": False,
        "event_timezone": "UTC",
        "task_acks_late": True,
        "task_acks_on_failure_or_timeout": False,
        "task_reject_on_worker_lost": True,
        "task_annotations": {
            "*": {
                "max_retries": MAX_RETRIES,
                "retry_backoff": True,
                "default_retry_delay": DEFAULT_RETRY_DELAY,
            }
        },
    }
)

# Autodiscover tasks
app.autodiscover_tasks(CELERY_AUTODISCOVER_TASKS, force=True)


@setup_logging.connect
def setup_loggers(*args, **kwargs):
    """
    Initialize aleph custom logging.

    Reconfigures root logger for colored output on console and custom
    formatting.
    """
    root_logger = logging.getLogger()

    if not settings.has_option("logging"):
        return False

    log_options = settings.get("logging")
    version_info = settings.get("version")
    version = version_info["tag"]

    if "format" not in log_options:
        log_tail = " %(name)s/%(funcName)s %(levelname)s: %(message)s"
        log_options["format"] = "%(asctime)s " + version + log_tail

    if "level" not in log_options:
        log_options["level"] = "WARNING"

    # Install colored console handler
    coloredlogs.install(level=log_options["level"], fmt=log_options["format"])

    # Add file handler if configured
    if "path" in log_options:
        # FileHandler
        fh = logging.FileHandler(log_options["path"])
        formatter = logging.Formatter(log_options["format"])
        fh.setFormatter(formatter)
        root_logger.addHandler(fh)

    # Install filter on root logger handlers
    class AlephLogsFilter(logging.Filter):
        def filter(self, record):
            return record.name.startswith("aleph")

    for handler in root_logger.handlers:
        handler.addFilter(AlephLogsFilter())

    LOGGER.debug("Logging setup successful.")


@celeryd_init.connect
def init_app(sender, instance, **kwargs):
    """
    Initialize application.

    * Adds worker name to app settings
    * Adds version info from git repo to app settings
    """
    settings.set("worker_name", "{0}".format(sender))
    with open("version.txt", "r") as version:
        version_text = version.read().strip()
        version_parts = version_text.split(" ")
        version_info = {
            "branch": version_parts[0],
            "tag": version_parts[1],
            "rev": version_parts[2],
            "hash": version_parts[3],
        }
        settings.set("version", version_info)


@celeryd_after_setup.connect
def after_setup(*args, **kwargs):
    """
    Execute post-setup routines.

    * Display log information indicating worker is setup and starting.
    """
    version = settings.get("version")
    version_tag = f"{version['tag']}-r{version['rev']} ({version['hash']})"
    print(ASCII_ART_ALEPH_LOGO % version_tag)
    LOGGER.info("Aleph worker is starting.")


@worker_ready.connect
def worker_ready(*args, **kwargs):
    """Execute routines after the worker is running and ready to accept jobs."""
    LOGGER.info("Aleph worker is online.")
