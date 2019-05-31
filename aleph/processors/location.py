import json

from aleph.models import Processor
from aleph.helpers.geolocation import get_location_for_address


class Location(Processor):

    filetypes = ["meta/location"]

    def process(self, sample):

        sample_data = sample["data"]
        ascii_data = sample_data.decode("utf-8")
        latlng = json.loads(ascii_data)

        metadata = {"geo_coordinates": latlng}

        geo = get_location_for_address(
            "%s, %s" % (latlng["latitude"], latlng["longitude"])
        )

        if geo:
            metadata["city"] = geo.city if geo.city else None
            metadata["country"] = geo.country if geo.country else None
            metadata["country_code"] = (
                geo.country_code.upper() if geo.country_code else None
            )
            metadata["state"] = geo.state if geo.state else None
            metadata["city"] = geo.city if geo.city else None
            metadata["postal"] = geo.postal if geo.postal else None

        return metadata
