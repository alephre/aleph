from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, Resolver
from netaddr.core import AddrFormatError
from tld import get_tld
from whois import whois

from aleph.helpers.validators import validate_domain, validate_ip
from aleph.models import Processor


class Domain(Processor):

    filetypes = ["meta/domain"]

    default_options = {
        "enabled": True,
        "nameservers": ["1.1.1.1", "8.8.8.8", "8.8.4.4"],
    }
    resolver = None

    def setup(self):

        self.resolver = Resolver()
        self.resolver.nameservers = self.options.get("nameservers")

        self.extracted_iocs = {
            "urls": set(),
            "domains": set(),
            "email_addresses": set(),
            "ipv4s": set(),
        }

    def process(self, sample):

        sample_data = sample["data"]
        domain = sample_data.decode("utf-8")

        # Add ourselves as an IOC
        self.extracted_iocs["domains"].add(domain)

        # Basic domain parameters
        metadata = {"entry_data": domain}

        # Parse domain
        domain_info = get_tld(
            domain, fix_protocol=True, fail_silently=True, as_object=True
        )

        if domain_info:
            metadata["domain"] = domain_info.domain
            metadata["tld"] = domain_info.tld
            metadata["fld"] = domain_info.fld
            metadata["subdomain"] = domain_info.subdomain

            # If fld is different (we're a subdomain), add to IOCs as well
            if metadata["fld"] is not metadata["entry_data"]:
                self.extracted_iocs["domains"].add(metadata["fld"])

        # Perform WHOIS lookup
        metadata["whois"] = self.get_whois(domain_info.fld)

        # Perform DNS lookups
        metadata["dns_records"] = self.perform_dns_lookups(domain)

        # Extract IOCs
        for ioc_type, ioc_values in self.extracted_iocs.items():
            self.add_ioc(ioc_type, list(ioc_values))

        # Extract meta samples
        for ip_addr in self.extracted_iocs["ipv4s"]:
            self.extract_meta_sample("host", ip_addr, sample["id"])

        # @ FIXME needs exists() to be implemented, otherwise endless recursion
        # for domain in extracted_iocs['domains']:
        #    if domain is not metadata['entry_data']:
        #        self.extract_meta_sample('domain', domain, sample['id'])

        return metadata

    def perform_dns_lookups(self, ip_addr):

        dns_records = {"a": [], "mx": [], "ns": [], "txt": []}

        for record_type, records in dns_records.items():

            try:

                dns_query = self.resolver.query(ip_addr, record_type.upper())

                for dns_record in dns_query:

                    record_str = str(dns_record)
                    record_host = record_str

                    if record_type == "mx":
                        mx_parts = record_str.split(" ")
                        mx_host = mx_parts[1][:-1]
                        record_host = {"host": mx_host, "prio": mx_parts[0]}
                    elif record_type == "ns":
                        record_host = record_str[:-1]  # cut off trailing dot

                    records.append(record_host)

                    # Extract IOCs from DNS entries
                    if record_type != "txt":
                        if record_type == "mx":
                            _host = record_host["host"]
                        else:
                            _host = record_host
                        if validate_ip(_host):
                            self.extracted_iocs["ipv4s"].add(_host)
                        elif validate_domain(_host):
                            self.extracted_iocs["domains"].add(_host.lower())

            except (NoNameservers, NoAnswer, NXDOMAIN, Timeout, AddrFormatError) as e:
                self.logger.warn("Error performing dns query: %s" % str(e))
            except Exception as e:
                self.logger.error("Unexpected error running DNS query: %s" % str(e))

        return dns_records

    def get_whois(self, fld):

        try:

            ret = whois(fld)

            # Extract IOCs from WHOIS information
            if ret["whois_server"]:
                self.extracted_iocs["domains"].add(ret["whois_server"])

            if ret["name_servers"]:
                for ns in ret["name_servers"]:
                    self.extracted_iocs["domains"].add(ns)

            if ret["emails"]:
                if isinstance(ret["emails"], list):
                    for e_addr in ret["emails"]:
                        self.extracted_iocs["email_addresses"].add(e_addr)
                else:
                    self.extracted_iocs["email_addresses"].add(ret["emails"])

            return ret

        except Exception as e:
            self.logger.warn("Error performing whois query:% s" % str(e))

        return None
