import os
import geocoder

from geoip2.database import Reader
from celery.utils.log import get_task_logger

from aleph.config.constants import (
    GEOLOCATION_DATABASE_PATH,
    GEOLOCATION_DATABASE_ASN,
    GEOLOCATION_DATABASE_CITY,
)

logger = get_task_logger(__name__)


def get_location_for_address(addr_str):

    try:
        geo = geocoder.osm(addr_str)
        return geo
    except Exception as e:
        logger.warn("Failed retrieving geo info for %s: %s" % (addr_str, str(e)))
        return None


def get_location_for_ip(ip_addr):

    try:
        reader = Reader(
            os.path.join(GEOLOCATION_DATABASE_PATH, GEOLOCATION_DATABASE_CITY)
        )
        return reader.city(ip_addr)
    except Exception as e:
        logger.warn("Failed retrieving geoip info for %s: %s" % (ip_addr, str(e)))
        return None


def get_asn_for_ip(ip_addr):

    try:
        reader = Reader(
            os.path.join(GEOLOCATION_DATABASE_PATH, GEOLOCATION_DATABASE_ASN)
        )
        return reader.asn(ip_addr)
    except Exception as e:
        logger.warn("Failed retrieving asn info for %s: %s" % (ip_addr, str(e)))
        return None
