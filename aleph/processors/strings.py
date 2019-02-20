import string
import re

from aleph.common.base import ProcessorBase
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
IPV4_REGEX = re.compile(r'[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]')
IPV6_REGEX = re.compile(r'(::|(([a-fA-F0-9]{1,4}):){7}(([a-fA-F0-9]{1,4}))|(:(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){1,6}:)|((([a-fA-F0-9]{1,4}):)(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){2}(:([a-fA-F0-9]{1,4})){1,5})|((([a-fA-F0-9]{1,4}):){3}(:([a-fA-F0-9]{1,4})){1,4})|((([a-fA-F0-9]{1,4}):){4}(:([a-fA-F0-9]{1,4})){1,3})|((([a-fA-F0-9]{1,4}):){5}(:([a-fA-F0-9]{1,4})){1,2}))', re.IGNORECASE | re.S)

PDB_REGEX = re.compile(r'\.pdb$', re.IGNORECASE)
URL_REGEX = re.compile(r'(?#WebOrIP)((?#protocol)((http|https):\/\/)?(?#subDomain)(([a-zA-Z0-9]+\.(?#domain)[a-zA-Z0-9\-]+(?#TLD)(\.[a-zA-Z]+){1,2})|(?#IPAddress)((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])))+(?#Port)(:[1-9][0-9]*)?)+(?#Path)((\/((?#dirOrFileName)[a-zA-Z0-9_\-\%\~\+]+)?)*)?(?#extension)(\.([a-zA-Z0-9_]+))?(?#parameters)(\?([a-zA-Z0-9_\-]+\=[a-z-A-Z0-9_\-\%\~\+]+)?(?#additionalParameters)(\&([a-zA-Z0-9_\-]+\=[a-z-A-Z0-9_\-\%\~\+]+)?)*)?', re.U | re.IGNORECASE)
GET_POST_REGEX = re.compile('(GET|POST) ')
HOST_REGEX = re.compile('Host: ')
USERAGENT_REGEX = re.compile(r'(Mozilla|curl|Wget|Opera)/.+\(.+\;.+\)', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'([\w\d\-\.]+)@{1}(([\w\d\-]{1,67})|([\w\d\-]+\.[\w\d\-]{1,67}))\.(([a-zA-Z\d]{2,4})(\.[a-zA-Z\d]{2})?)', re.IGNORECASE)
REGKEY_REGEX = re.compile('(HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG|HKCR|HKCU|HKLM|HKU|HKCC)(/|\x5c\x5c)', re.IGNORECASE)
REGKEY2_REGEX = re.compile(r'(CurrentVersion|Software\\Microsoft|Windows NT|Microsoft\\Interface)')
FILE_REGEX = re.compile(r'\b([\w,%-.]+\.[A-Za-z]{3,4})\b', re.U | re.IGNORECASE)

class StringsProcessor(ProcessorBase):

    name = 'strings'
    mimetypes_except = MIMETYPES_ARCHIVE + ['text/url']

    classifiers = {}

    def setup(self):

        self.classifiers['domains'] = (DOMAIN_REGEX,)
        self.classifiers['ips'] = (IPV4_REGEX, IPV6_REGEX)
        self.classifiers['urls'] = (URL_REGEX,)
        self.classifiers['files'] = (FILE_REGEX,)
        self.classifiers['emails'] = (EMAIL_REGEX,)
        self.classifiers['http_headers'] = (HOST_REGEX, USERAGENT_REGEX, GET_POST_REGEX)
        self.classifiers['win32'] = (REGKEY_REGEX, REGKEY2_REGEX, PDB_REGEX)
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
        _data = data.decode('utf-8', 'ignore')
        for c in _data:
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

    def process(self, sample):

        result = {
            'uncategorized': []
        }

        strings_found = list(self.strings(sample['data']))

        for s in strings_found:

            string_classified = False

            for classifier, regexes in self.classifiers.items():

                if classifier not in result:
                    result[classifier] = []

                for regex in regexes:
                    if regex.search(s):
                        result[classifier].append(s)
                        string_classified = True

            if not string_classified:
                result['uncategorized'].append(s)

        return result
