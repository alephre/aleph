from copy import deepcopy
from ioc_finder import find_iocs as if_find_iocs
from iocextract import extract_urls, extract_ipv4s, extract_ipv6s, extract_emails, extract_md5_hashes, extract_sha1_hashes, extract_sha256_hashes, extract_sha512_hashes, extract_custom_iocs

from aleph.helpers.validators import validate_domain, validate_ip, validate_url, validate_email, validate_mac_address
from aleph.helpers.regexes import CRYPTO_WALLET_BITCOIN, CRYPTO_WALLET_BITCOIN_CASH, CRYPTO_WALLET_ETHEREUM, CRYPTO_WALLET_LITECOIN, CRYPTO_WALLET_DOGECOIN, CRYPTO_WALLET_DASH, CRYPTO_WALLET_MONERO, CRYPTO_WALLET_NEO, CRYPTO_WALLET_RIPPLE

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
    "bitcoincash_addresses": [],
    "ethereum_addresses": [],
    "litecoin_addresses": [],
    "dogecoin_addresses": [],
    "dash_addresses": [],
    "monero_addresses": [],
    "neo_addresses": [],
    "ripple_addresses": [],
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
 
def get_validator(ioc_type):

    validator = None

    if ioc_type in validators.keys():
        validator = validators[ioc_type]

    return validator

def find_iocs(text):

    iocs = deepcopy(default_values)

    # Custom IOCs
    custom_funcs = {
        "bitcoin_addresses": [ CRYPTO_WALLET_BITCOIN ,],
        "bitcoincash_addresses": [ CRYPTO_WALLET_BITCOIN_CASH, ],
        "ethereum_addresses": [ CRYPTO_WALLET_ETHEREUM, ],
        "litecoin_addresses": [ CRYPTO_WALLET_LITECOIN, ],
        "dogecoin_addresses": [ CRYPTO_WALLET_DOGECOIN, ],
        "dash_addresses": [ CRYPTO_WALLET_DASH, ],
        "monero_addresses": [ CRYPTO_WALLET_MONERO, ],
        "neo_addresses":  [ CRYPTO_WALLET_NEO, ] ,
        "ripple_addresses": [ CRYPTO_WALLET_RIPPLE, ],
    }

    for ioc_type, ioc_regexes in custom_funcs.items():

        validator = get_validator(ioc_type)

        for ioc in extract_custom_iocs(text, ioc_regexes):
            if validator and not validator(ioc):
                continue

    # IOC Extract
    no_refang = ["ipv6s", "md5s", "sha1s", "sha256s", "sha512s"]
    iocextract_funcs = {
        "ipv4s": extract_ipv4s,
        "ipv6s": extract_ipv6s,
        "urls": extract_urls,
        "email_addresses": extract_emails,
        "md5s": extract_md5_hashes,
        "sha1s": extract_sha1_hashes,
        "sha256s": extract_sha256_hashes,
        "sha512s": extract_sha512_hashes,
    }

    for ioc_type, ioc_func in iocextract_funcs.items():

        validator = get_validator(ioc_type)
        if ioc_type in no_refang:
            ioc_values = ioc_func(text)
        else:
            ioc_values = ioc_func(text, refang=True)

        for ioc in ioc_values:
            if validator and not validator(ioc):
                continue
            iocs[ioc_type].append(ioc)

    # IOC Finder
    ioc_finder_res = if_find_iocs(text)

    for ioc_type, ioc_values in ioc_finder_res.items():

        validator = get_validator(ioc_type)

        for ioc in ioc_values:
            if validator and not validator(ioc):
                continue
            iocs[ioc_type].append(ioc)

    return {k: list(set(v)) for k, v in iocs.items() if len(v) > 0}
