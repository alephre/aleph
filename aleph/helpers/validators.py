from ipaddress import ip_address
from tld import get_tld
from urllib.parse import urlparse

def validate_domain(domain):

    return (get_tld(domain, fail_silently=True) is not None)

def validate_url(url):

    parsed = urlparse(url)

    return (parsed.netloc) 

def validate_ip(ipaddr):

    try:
        ipa = ip_address(ipaddr)
        return True
    except ValueError:
        return False
