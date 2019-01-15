import string

from aleph.base import ProcessorBase
from aleph.constants import MIMETYPES_ARCHIVE

class StringsProcessor(ProcessorBase):

    name = 'strings'
    mimetypes_except = MIMETYPES_ARCHIVE + ['text/url']

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

        result = {}
        result['strings'] = list(self.strings(sample['data']))
        return result
