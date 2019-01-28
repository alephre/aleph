import string
import re

from aleph.common.base import ProcessorBase
from aleph.config.constants import MIMETYPES_ARCHIVE

# Some of the Regex below were taken from https://github.com/viper-framework/viper/blob/master/viper/modules/strings.py

DOMAIN_REGEX = re.compile(r'([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.)+[a-z0-9][a-z0-9\-]*[a-z0-9]', re.IGNORECASE)
IPV4_REGEX = re.compile(r'[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]')
IPV6_REGEX = re.compile(r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}'
                        r'|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9'
                        r'A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25['
                        r'0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3'
                        r'})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|['
                        r'1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,'
                        r'4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:'
                        r'))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-'
                        r'5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]'
                        r'{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d'
                        r'\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7}'
                        r')|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d'
                        r'\d|[1-9]?\d)){3}))|:)))(%.+)?', re.IGNORECASE | re.S)

PDB_REGEX = re.compile(r'\.pdb$', re.IGNORECASE)
URL_REGEX = re.compile(r'(?i)\b((?:http[s]?:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s!()\[\]{};:\'".,<>?]))', re.U | re.IGNORECASE)
GET_POST_REGEX = re.compile('(GET|POST) ')
HOST_REGEX = re.compile('Host: ')
USERAGENT_REGEX = re.compile(r'(Mozilla|curl|Wget|Opera)/.+\(.+\;.+\)', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'((?:(?:[A-Za-z0-9]+_+)|(?:[A-Za-z0-9]+\-+)|(?:[A-Za-z0-9]+\.+)|(?:[A-Za-z0-9]+\++))*[A-Za-z0-9]+@(?:(?:\w+\-+)|(?:\w+\.))*\w{1,63}\.[a-zA-Z]{2,6})', re.IGNORECASE)
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
