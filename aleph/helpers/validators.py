from ipaddress import ip_address, IPv4Address, IPv6Address
from tld import get_tld
from urllib.parse import urlparse

def validate_domain(domain):

    return (get_tld(domain, fail_silently=True) is not None)

def validate_url(url):

    parsed = urlparse(url)

    return (parsed.netloc) 

def validate_ip(ipaddr, ip_versions=[4, 6]):

    try:
        ipa = ip_address(ipaddr)

        if isinstance(ipa, IPv4Address) and 4 in ip_versions:
            return ipa

        if isinstance(ipa, IPv6Address) and 6 in ip_versions:
            return ipa

        return None
    except ValueError:
        return False
