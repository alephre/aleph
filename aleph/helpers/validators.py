from validators import domain, email, url, ipv4, ipv6, mac_address
from ipaddress import ip_address, IPv4Address, IPv6Address
from tld import get_tld
from urllib.parse import urlparse

def validate_domain(domain_str, domain_min_length=2):

    res = get_tld(domain_str, as_object=True, fix_protocol=True, fail_silently=True)

    if not res:
        return False

    if len(res.domain) < domain_min_length:
        return False

    return (domain(res.fld))

def validate_url(url_str):

    if not url(url_str):
        return False

    # @FIXME overkill?
    parsed = urlparse(url_str)

    if parsed.netloc:
        return validate_domain(parsed.netloc)

    return False

def validate_ip(ipaddr, ip_versions=[4, 6], ignore_addrs=['0.0.0.0']):

    if ipaddr in ignore_addrs:
        return False

    try:
        ipa = ip_address(ipaddr)

        if isinstance(ipa, IPv4Address) and 4 in ip_versions:
            return (ipv4(ipaddr))

        if isinstance(ipa, IPv6Address) and 6 in ip_versions:
            return (ipv6(ipaddr))

        return False
    except ValueError:
        return False

def validate_mac_address(mac_addr):

    return (mac_address(mac_addr))

def validate_email(email_addr):

    return (email(email_addr))
