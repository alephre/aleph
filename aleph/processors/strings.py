import re
import string

from netaddr import IPNetwork

from aleph.common.base import Processor
from aleph.config.constants import MIMETYPES_ARCHIVE

# Some of the Regex below were taken from https://github.com/viper-framework/viper/blob/master/viper/modules/strings.py

CRYPTO_WALLET_BITCOIN = re.compile("^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
CRYPTO_WALLET_BITCOIN_CASH = re.compile("^[13][a-km-zA-HJ-NP-Z1-9]{33}$")
CRYPTO_WALLET_ETHEREUM = re.compile("^0x[a-fA-F0-9]{40}$")
CRYPTO_WALLET_LITECOIN = re.compile("^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$")
CRYPTO_WALLET_DOGECOIN = re.compile("^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$")
CRYPTO_WALLET_DASH = re.compile("^X[1-9A-HJ-NP-Za-km-z]{33}$")
CRYPTO_WALLET_MONERO = re.compile("^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")
CRYPTO_WALLET_NEO = re.compile("^A[0-9a-zA-Z]{33}$")
CRYPTO_WALLET_RIPPLE = re.compile("^r[0-9a-zA-Z]{33}$")

DOMAIN_REGEX = re.compile(r'([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.)+[a-z0-9][a-z0-9\-]*[a-z0-9]', re.IGNORECASE)
IPV4_REGEX = re.compile(r'''((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))''', re.MULTILINE)
IPV6_REGEX = re.compile(r'(::|(([a-fA-F0-9]{1,4}):){7}(([a-fA-F0-9]{1,4}))|(:(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){1,6}:)|((([a-fA-F0-9]{1,4}):)(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){2}(:([a-fA-F0-9]{1,4})){1,5})|((([a-fA-F0-9]{1,4}):){3}(:([a-fA-F0-9]{1,4})){1,4})|((([a-fA-F0-9]{1,4}):){4}(:([a-fA-F0-9]{1,4})){1,3})|((([a-fA-F0-9]{1,4}):){5}(:([a-fA-F0-9]{1,4})){1,2}))', re.IGNORECASE | re.S)

# Added CVE regex pattern
CVE_REGEX = re.compile("(CVE-(19|20)\\d{2}-\\d{4,7})", re.I | re.S | re.M)

# Make sure there is something before ".pdb"
PDB_REGEX = re.compile(r'\w+\.pdb$', re.IGNORECASE)

# matches more content than original URL_REGEX pattern (hxxps, https, ftpx)
URL_REGEX = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?]))''', re.VERBOSE | re.MULTILINE)

# GET, POST, and Host: will always start at the beginning of the line in HTTP headers
GET_POST_REGEX = re.compile('^(GET|POST)')
HOST_REGEX = re.compile('^Host: ')
USERAGENT_REGEX = re.compile(r'(Mozilla|curl|Wget|Opera|Safari|Edge|Lynx)/.+\(.+\;.+\)', re.IGNORECASE)

EMAIL_REGEX = re.compile(r'([\w\d\-\.]+)@{1}(([\w\d\-]{1,67})|([\w\d\-]+\.[\w\d\-]{1,67}))\.(([a-zA-Z\d]{2,4})(\.[a-zA-Z\d]{2})?)', re.IGNORECASE)

REGKEY_REGEX = re.compile('(HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG|HKCR|HKCU|HKLM|HKU|HKCC)(/|\x5c\x5c)', re.IGNORECASE)
REGKEY2_REGEX = re.compile(r'(CurrentVersion|Software\\Microsoft|Windows NT|Microsoft\\Interface)')

# Updated file regex with common file types to match more file types and .* files
FILE_REGEX = re.compile(r'([a-zA-Z0-9\s_\\.\-\(\):])+(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt|html|php|js|exe|dll|jar|zip|zipx|7z|rar|tar|gz|jpeg|jpg|gif|png|tiff|bmp|flv|swf)')

# Match files that use double extensions to trick users such as Document.docx.exe or something
FILE_REGEX_DOUBLE_EXTENSIONS = re.compile(r'([a-zA-Z0-9\s_\\.\-\(\):])+(pdf|rar|zip|doc\w?|xls\w?|ppt\w?|xml|txt|lnk|jpg|js|jsp|jar|java|dll|exe)\.(pdf|rar|zip|doc\w?|xls\w?|ppt\w?|xml|txt|lnk|jpg|js|jsp|jar|java|dll|exe)')

# Hash patterns
MD5_REGEX = re.compile("\\b[a-f0-9]{32}\\b", re.I | re.S | re.M)
SHA1_REGEX = re.compile("\\b[a-f0-9]{40}\\b", re.I | re.S | re.M)
SHA256_REGEX = re.compile("\\b[a-f0-9]{64}\\b", re.I | re.S | re.M)
SHA512_REGEX = re.compile("\\b[a-f0-9]{128}\\b", re.I | re.S | re.M)
SSDEEP_REGEX = re.compile("\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M)

# mac address pattern
MAC_ADDR_REGEX = re.compile(r'\b(?i)(?:[0-9A-F]{2}[:-]){5}(?:[0-9A-F]{2})\b')


# @TODO: figure out if we want to process internal IPs or use this whitelist to remove reserved IPs
# whitelist = [{'net': IPNetwork('10.0.0.0/8'), 'org': 'Private per RFC 1918'},
#        {'net': IPNetwork('172.16.0.0/12'), 'org': 'Private per RFC 1918'},
#        {'net': IPNetwork('192.168.0.0/16'), 'org': 'Private per RFC 1918'},
#        {'net': IPNetwork('0.0.0.0/8'), 'org': 'Invalid per RFC 1122'},
#        {'net': IPNetwork('127.0.0.0/8'), 'org': 'Loopback per RFC 1122'},
#        {'net': IPNetwork('169.254.0.0/16'), 'org': 'Link-local per RFC 3927'},
#        {'net': IPNetwork('100.64.0.0/10'), 'org': 'Shared address space per RFC 6598'},
#        {'net': IPNetwork('192.0.0.0/24'), 'org': 'IETF Protocol Assignments per RFC 6890'},
#        {'net': IPNetwork('192.0.2.0/24'), 'org': 'Documentation and examples per RFC 6890'},
#        {'net': IPNetwork('192.88.99.0/24'), 'org': 'IPv6 to IPv4 relay per RFC 3068'},
#        {'net': IPNetwork('198.18.0.0/15'), 'org': 'Network benchmark tests per RFC 2544'},
#        {'net': IPNetwork('198.51.100.0/24'), 'org': 'Documentation and examples per RFC 5737'},
#        {'net': IPNetwork('203.0.113.0/24'), 'org': 'Documentation and examples per RFC 5737'},
#        {'net': IPNetwork('224.0.0.0/4'), 'org': 'IP multicast per RFC 5771'},
#        {'net': IPNetwork('240.0.0.0/4'), 'org': 'Reserved per RFC 1700'},
#        {'net': IPNetwork('255.255.255.255/32'), 'org': 'Broadcast address per RFC 919'}]



class StringsProcessor(Processor):

    name = 'strings'
    mimetypes_except = MIMETYPES_ARCHIVE + ['text/url']

    classifiers = {}

    def setup(self):

        self.classifiers['domains'] = (DOMAIN_REGEX,)
        self.classifiers['ips'] = (IPV4_REGEX, IPV6_REGEX)
        self.classifiers['urls'] = (URL_REGEX,)
        self.classifiers['hashes'] = (MD5_REGEX, SHA1_REGEX, SHA256_REGEX, SHA512_REGEX, SSDEEP_REGEX)
        self.classifiers['cves'] = (CVE_REGEX,)
        self.classifiers['files'] = (FILE_REGEX, FILE_REGEX_DOUBLE_EXTENSIONS)
        self.classifiers['emails'] = (EMAIL_REGEX,)
        self.classifiers['http_headers'] = (HOST_REGEX, USERAGENT_REGEX, GET_POST_REGEX)
        self.classifiers['win32'] = (REGKEY_REGEX, REGKEY2_REGEX, PDB_REGEX)
        self.classifiers['mac'] = (MAC_ADDR_REGEX, )
        self.classifiers['cryptocurrency_wallet'] = (
            CRYPTO_WALLET_BITCOIN,
            CRYPTO_WALLET_BITCOIN_CASH,
            CRYPTO_WALLET_ETHEREUM,
            CRYPTO_WALLET_LITECOIN,
            CRYPTO_WALLET_DOGECOIN,
            CRYPTO_WALLET_DASH,
            CRYPTO_WALLET_MONERO,
            CRYPTO_WALLET_NEO,
            )


    def strings(self, data, min=4):
        result = ""
        #_data = data.decode('utf-8', 'backslashreplace')
        for c in data:
            if chr(c) in string.printable:
                result += chr(c)
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result


    def process(self, sample):

        result = {
            'uncategorized': set()
        }

        strings_found = list(self.strings(sample['data']))

        for s in strings_found:

            string_classified = False

            for classifier, regexes in self.classifiers.items():

                if classifier not in result:
                    result[classifier] = set()

                for regex in regexes:
                    if regex.search(s):
                        result[classifier].add(s)
                        string_classified = True

            if not string_classified:
                result['uncategorized'].add(s)

        # Convert sets to lists because JSON can't handle sets
        return dict((k, list(v)) for k, v in result.items())
