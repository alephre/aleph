import json

from ipaddress import ip_address, IPv6Address

from aleph.models import Processor
from aleph.helpers.geolocation import get_location_for_ip, get_asn_for_ip

class Host(Processor):

    filetypes = ['meta/host']

    def process(self, sample):

        sample_data = sample['data']
        ascii_data = sample_data.decode("utf-8")

        ip_info = ip_address(ascii_data)

        metadata = {
            'ip': ascii_data,
            'reverse_pointer': ip_info.reverse_pointer,
            'ip_version': 6 if isinstance(ip_info, IPv6Address) else 4,
            'is_global': ip_info.is_global,
            'is_private': ip_info.is_private,
            'is_loopback': ip_info.is_loopback,
            'is_link_local': ip_info.is_link_local,
            'is_reserved': ip_info.is_reserved,
            'is_multicast': ip_info.is_multicast,
            'is_unspecified': ip_info.is_unspecified,

        }

        # Add ourselves as an IOC
        ioc_type = 'ipv4s' if metadata['ip_version'] is 4 else 'ipv6s'
        self.add_ioc(ioc_type, [metadata['ip'],])

        if ip_info.is_global and metadata['ip_version'] is 4:

            geo = get_location_for_ip(ascii_data)
            asn = get_asn_for_ip(ascii_data)

            if geo:

                metadata['city'] = geo.city.name if geo.city.name else None
                metadata['state'] = geo.subdivisions.most_specific.name if geo.subdivisions.most_specific.name else None
                metadata['country'] = geo.country.name if geo.country.name else None
                metadata['country_code'] = geo.country.iso_code if geo.country.iso_code else None
                metadata['postal'] = geo.postal.code if geo.postal else None
                metadata['geo_coordinates'] = {'latitude': geo.location.latitude, 'longitude': geo.location.longitude} if geo.location else None

            if asn:
                metadata['asn'] = asn.autonomous_system_number
                metadata['as_org'] = asn.autonomous_system_organization

        if 'geo_coordinates' in metadata.keys():

            self.extract_meta_sample('location', json.dumps(metadata['geo_coordinates']), sample['id'])

        return metadata
