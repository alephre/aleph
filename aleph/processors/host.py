import json

from slugify import slugify 

from aleph.common.base import Processor
from aleph.helpers.geolocation import get_location_for_ip

class Host(Processor):

    filetypes = ['meta/host']

    def process(self, sample):

        sample_data = sample['data']
        ascii_data = sample_data.decode("utf-8")

        metadata = {
            'ip': ascii_data,
        }

        geo = get_location_for_ip(ascii_data)

        if geo:

            if geo.org:
                asn = geo.org[2:6]
                isp = geo.org[7:]

                metadata['asn'] = asn
                metadata['isp'] = isp

            metadata['city'] = geo.city if geo.city else None
            metadata['state'] = geo.state if geo.state else None
            metadata['country'] = geo.country if geo.country else None
            metadata['postal'] = geo.postal if geo.postal else None
            metadata['latlng'] = geo.latlng if geo.latlng else None

        return metadata

        if metadata['latlng']:

            self.extract_location_sample(metadata['latlng'], sample['id'])

        return metadata

    def extract_location_sample(self, latlng, parent_id):

        metadata = {
            'filetype': 'meta/location',
            'filetype_desc': 'location extracted from IP address'
        }
        filename = '%s.location.meta' % slugify(latlng).lower()
        filedata = bytes(json.dumps(latlng), 'utf-8')

        self.dispatch(filedata, metadata=metadata, filename=filename, parent=parent_id)
