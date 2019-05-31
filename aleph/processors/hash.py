import hashlib
import binascii
import ssdeep

from aleph.models import Processor


class Hash(Processor):
    def process(self, sample):

        sample_data = sample["data"]

        hashes = {
            "md5": hashlib.md5(sample_data).hexdigest(),
            "sha1": hashlib.sha1(sample_data).hexdigest(),
            "sha256": hashlib.sha256(sample_data).hexdigest(),
            "sha512": hashlib.sha512(sample_data).hexdigest(),
            "crc32": "%08X" % (binascii.crc32(sample_data) & 0xFFFFFFFF),
            "ssdeep": ssdeep.hash(sample_data),
        }

        return hashes
