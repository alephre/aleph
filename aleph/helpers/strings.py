import re

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def in_string(tokens, string):
    return any(token in str(string).lower() for token in tokens)


def normalize_name(name):
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
