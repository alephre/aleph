import binascii
import hashlib

import ssdeep

from aleph.models import Processor


class Hash(Processor):
    def process(self, sample):

        sample_data = sample["data"]

        hashes = {
            "md5": hashlib.md5(sample_data).hexdigest(),  # nosec
            "sha1": hashlib.sha1(sample_data).hexdigest(),  # nosec
            "sha256": hashlib.sha256(sample_data).hexdigest(),  # nosec
            "sha512": hashlib.sha512(sample_data).hexdigest(),  # nosec
            "crc32": "%08X" % (binascii.crc32(sample_data) & 0xFFFFFFFF),  # nosec
            "ssdeep": ssdeep.hash(sample_data),
        }

        return hashes
