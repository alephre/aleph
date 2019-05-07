from copy import deepcopy
from ioc_finder import find_iocs as if_find_iocs
from iocextract import extract_urls, extract_ips, extract_emails

from aleph.helpers.validators import validate_domain, validate_ip, validate_url, validate_email, validate_mac_address

validators = {
    "urls": validate_url,
    "domains": validate_domain,
    "ipv4": validate_ip,
    "ipv6": validate_ip,
    "mac_addresses": validate_mac_address,
    "email_addresses": validate_email,
    "email_addresses_complete": validate_email,
}

default_values = {
    "asns": [],
    "authentihashes": [],
    "bitcoin_addresses": [],
    "cves": [],
    "domains": [],
    "email_addresses": [],
    "email_addresses_complete": [],
    "file_paths": [],
    "google_adsense_publisher_ids": [],
    "google_analytics_tracker_ids": [],
    "imphashes": [],
    "ipv4_cidrs": [],
    "ipv4s": [],
    "ipv6s": [],
    "mac_addresses": [],
    "md5s": [],
    "phone_numbers": [],
    "registry_key_paths": [],
    "sha1s": [],
    "sha256s": [],
    "sha512s": [],
    "ssdeeps": [],
    "urls": [],
    "user_agents": [],
    "xmpp_addresses": []
}
 
def find_iocs(text):

    iocs = deepcopy(default_values)

    # IOC Extract
    iocextract_funcs = {
        "urls": extract_urls,
        "email_addresses": extract_emails,
    }

    for ioc_type, ioc_func in iocextract_funcs.items():

        validator = None

        if ioc_type in validators.keys():
            validator = validators[ioc_type]

        for ioc in ioc_func(text, refang=True):
            if validator and not validator(ioc):
                continue
            iocs[ioc_type].append(ioc)

    # IOC Finder
    ioc_finder_res = if_find_iocs(text)

    for ioc_type, ioc_values in ioc_finder_res.items():

        validator = None

        if ioc_type in validators.keys():
            validator = validators[ioc_type]

        for ioc in ioc_values:
            if validator and not validator(ioc):
                continue
            iocs[ioc_type].append(ioc)

    return {k: list(set(v)) for k, v in iocs.items() if len(v) > 0}
