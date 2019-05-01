import geocoder

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

def get_location_for_ip(ip_addr):

    return geocoder.ip(ip_addr)
