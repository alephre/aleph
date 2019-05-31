from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def to_es_date(d):
    s = d.strftime("%Y-%m-%dT%H:%M:%S.")
    s += "%03d" % int(round(d.microsecond / 1000.0))
    s += d.strftime("%z")
    return s
