import json

from slugify import slugify 
from ipaddress import ip_address, IPv6Address

from aleph.common.base import Processor
from aleph.helpers.geolocation import get_location_for_ip, get_asn_for_ip

class Host(Processor):

    filetypes = ['meta/host']

    def process(self, sample):

        sample_data = sample['data']
        ascii_data = sample_data.decode("utf-8")

        ip_info = ip_address(ascii_data)

        metadata = {
            'ip': ascii_data,
            'ip_version': 6 if isinstance(ip_info, IPv6Address) else 4,
            'is_global': ip_info.is_global,
            'is_private': ip_info.is_private,
            'is_loopback': ip_info.is_loopback,
            'is_link_local': ip_info.is_link_local,
        }

        if ip_info.is_global and metadata['ip_version'] is 4:

            geo = get_location_for_ip(ascii_data)
            asn = get_asn_for_ip(ascii_data)

            if geo:

                metadata['city'] = geo.city.name if geo.city.name else None
                metadata['state'] = geo.subdivisions.most_specific.name if geo.subdivisions.most_specific.name else None
                metadata['country'] = geo.country.name if geo.country.name else None
                metadata['country_code'] = geo.country.iso_code if geo.country.iso_code else None
                metadata['postal'] = geo.postal.code if geo.postal else None
                metadata['latlng'] = [geo.location.latitude, geo.location.longitude] if geo.location else None

            if asn:
                metadata['asn'] = asn.autonomous_system_number
                metadata['as_org'] = asn.autonomous_system_organization

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
