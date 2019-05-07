from tld import get_tld
from dns.resolver import Resolver, NoAnswer, NoNameservers, NXDOMAIN
from dns.exception import Timeout

from aleph.models import Processor
from aleph.exceptions import ProcessorRuntimeException
from aleph.helpers.validators import validate_domain, validate_ip

class Domain(Processor):

    filetypes = ['meta/domain']

    #default_options = { 'nameservers': ['8.8.8.8', '8.8.4.4'] }
    resolver = None

    def setup(self):

        self.resolver = Resolver()
        #self.resolver.nameservers = self.options.get('nameservers')

    def process(self, sample):

        sample_data = sample['data']
        ascii_data = sample_data.decode("utf-8")

        # Basic domain parameters
        found_ips = set()
        found_domains = set()

        metadata = {
            'entry_data': ascii_data,
            'dns_records': {
                'a': [],
                'mx': [],
                'ns': [],
                'txt': [],
            },
        }
        # Parse domain
        domain_info = get_tld(ascii_data, fix_protocol=True, fail_silently=True, as_object=True)
        if domain_info:
            metadata['domain'] = domain_info.domain
            metadata['tld'] = domain_info.tld
            metadata['fld'] = domain_info.fld
            metadata['subdomain'] = domain_info.subdomain

        # Perform DNS lookups
        for record_type, records in metadata['dns_records'].items():

            try:

                dns_query = self.resolver.query(ascii_data, record_type.upper())

                for dns_record in dns_query:

                    record_str = str(dns_record)
                    record_host = record_str

                    if record_type is 'mx':
                        mx_parts = record_str.split(' ')
                        record_host = mx_parts[1][:-1] # cut off trailing dot
                        records.append({'host': record_host, 'prio': mx_parts[0]})
                    elif record_type is 'ns':
                        record_host = record_str[:-1] # cut off trailing dot
                        records.append(record_host)
                    else:
                        records.append(record_host)

                    if record_type is not 'txt':
                        if validate_ip(record_host):
                            found_ips.add(record_host)
                        elif validate_domain(record_host):
                            found_domains.add(record_host)

            except (NoNameservers, NoAnswer, NXDOMAIN, Timeout) as e:
                self.logger.warn('Error performing dns query: %s' % str(e))

        for ip_addr in found_ips:
            self.extract_meta_sample('host', ip_addr, sample['id'])

        # @FIXME not working, crazy recursion
        #for domain in found_domains:
        #    if domain is not metadata['entry_data']:
        #        self.extract_meta_sample('domain', domain, sample['id'])

        return metadata
