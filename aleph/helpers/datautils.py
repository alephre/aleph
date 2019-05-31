import math

from celery.utils.log import get_task_logger

from hashlib import sha256
from base64 import b64encode, b64decode
from collections import Counter

logger = get_task_logger(__name__)


def hash_data(data, algo=sha256):
    hasher = algo()
    hasher.update(data)
    return hasher.hexdigest()


def encode_data(data):
    return b64encode(data).decode("utf-8")


def decode_data(data):
    return b64decode(data.encode("utf-8"))


def entropy(data):
    """Calculate the entropy of a chunk of data."""
    if len(data) == 0:
        return 0.0

    occurences = Counter(bytearray(data))

    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x * math.log(p_x, 2)

    return entropy
