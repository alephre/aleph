import hashlib
import binascii

from aleph.common.base import AnalyzerBase

class HelloWorldAnalyzer(AnalyzerBase):

    default_options = {'enabled': False}

    def process(self, sample):
    
        return {'hello': 'world'}
