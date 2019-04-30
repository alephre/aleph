from slugify import slugify 
from dns.resolver import Resolver, NoAnswer

from aleph.common.base import Processor

class Domain(Processor):

    filetypes = ['meta/domain']
    resolver = None

    def setup(self):

        self.resolver = Resolver()

    def process(self, sample):

        sample_data = sample['data']
        ascii_data = sample_data.decode("utf-8")

        # Basic domain parameters
        found_ips = set()
        metadata = {
            'domain_part': None,
            'tld': None,
            'is_subdomain': False,
            'dns_records': {
                'a': [],
                'mx': [],
                'ns': [],
                'txt': [],
            },
        }

        # Perform DNS lookups
        for record_type, records in metadata['dns_records'].items():
            try:
                dns_query = self.resolver.query(ascii_data, record_type.upper())
                for dns_record in dns_query:
                    record_str = str(dns_record)
                    records.append(record_str)
                    if record_type is not 'txt':
                        found_ips.add(record_str)
            except NoAnswer as e:
                continue # No answer to given record type
            except Exception as e:
                self.logger.error('Error performing dns query: %s' % str(e))
                return False

        for ip_addr in found_ips:
            self.extract_host_sample(ip_addr, sample['id'])

        return metadata

    def extract_host_sample(self, host, parent_id):

        metadata = {
            'filetype': 'meta/host',
            'filetype_desc': 'host extracted from domain'
        }
        filename = '%s.host.meta' % slugify(host).lower()
        filedata = bytes(host, 'utf-8')

        self.dispatch(filedata, metadata=metadata, filename=filename, parent=parent_id)

