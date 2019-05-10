from whois import whois
from tld import get_tld
from dns.resolver import Resolver, NoAnswer, NoNameservers, NXDOMAIN
from dns.exception import Timeout

from aleph.models import Processor
from aleph.exceptions import ProcessorRuntimeException
from aleph.helpers.validators import validate_domain, validate_ip

class Domain(Processor):

    filetypes = ['meta/domain']

    default_options = { 'enabled': True, 'nameservers': ['1.1.1.1', '8.8.8.8', '8.8.4.4'] }
    resolver = None

    def setup(self):

        self.resolver = Resolver()
        self.resolver.nameservers = self.options.get('nameservers')

    def process(self, sample):

        sample_data = sample['data']
        ascii_data = sample_data.decode("utf-8")

        #@FIXME in this case, extract meta from IOCs can be ok. Gotta test
        extracted_iocs = {
            'urls': set(),
            'domains': set(),
            'email_addresses': set(),
            'ipv4s': set(),
        }

        # Basic domain parameters
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
        
        # Perform WHOIS lookup
        try:

            ret = whois(domain_info.fld)

            # Extract IOCs from WHOIS information
            if ret['whois_server']:
                extracted_iocs['domains'].add(ret['whois_server'])

            if ret['name_servers']:
                for ns in ret['name_servers']:
                    extracted_iocs['domains'].add(ns)

            if ret['emails']:
                if isinstance(ret['emails'], list):
                    for e_addr in ret['emails']:
                        extracted_iocs['email_addresses'].add(e_addr)
                else:
                    extracted_iocs['email_addresses'].add(ret['emails'])
            

            metadata['whois'] = ret 

        except Exception as e:
            self.logger.warn('Error performing whois query:% s' % str(e))

        # Perform DNS lookups
        for record_type, records in metadata['dns_records'].items():

            try:

                dns_query = self.resolver.query(ascii_data, record_type.upper())

                for dns_record in dns_query:

                    record_str = str(dns_record)
                    record_host = record_str

                    if record_type is 'mx':
                        mx_parts = record_str.split(' ')
                        mx_host = mx_parts[1][:-1]
                        record_host = {'host': mx_host, 'prio': mx_parts[0]}
                    elif record_type is 'ns':
                        record_host = record_str[:-1] # cut off trailing dot

                    records.append(record_host)

                    # Extract IOCs from DNS entries
                    if record_type is not 'txt':
                        if record_type is 'mx':
                            _host = record_host['host']
                        else:
                            _host = record_host
                        if validate_ip(_host):
                            extracted_iocs['ipv4s'].add(_host)
                        elif validate_domain(_host):
                            extracted_iocs['domains'].add(_host.lower())

            except (NoNameservers, NoAnswer, NXDOMAIN, Timeout) as e:
                self.logger.warn('Error performing dns query: %s' % str(e))
            except Exception as e:
                self.logger.error('Unexpected error running DNS query: %s' % str(e))

        # Extract IOCs
        for ioc_type, ioc_values in extracted_iocs.items():
            self.add_ioc(ioc_type, list(ioc_values))

        # Extract meta samples
        for ip_addr in extracted_iocs['ipv4s']:
            self.extract_meta_sample('host', ip_addr, sample['id'])

        # @FIXME not working, crazy recursion
        #for domain in found_domains:
        #    if domain is not metadata['entry_data']:
        #        self.extract_meta_sample('domain', domain, sample['id'])

        return metadata
