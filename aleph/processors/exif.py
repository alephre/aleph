import piexif

from io import BytesIO
from aleph.common.base import Processor

class EXIF(Processor):

    default_options = {'enabled': True}
    filetypes = [
        'image/jpeg',
        'image/tiff',
        ]

    def process(self, sample):

        sample_data = sample['data']

        try:
            _exif = piexif.load(sample_data)
        except Exception as e:
            self.logger.warn('Unable to parse EXIF data for sample %s: %s' % (sample['id'], str(e)))

        result = {}

        for ifd in ("0th", "Exif", "GPS", "1st"):
            for tag in _exif[ifd]:
                tag_name = piexif.TAGS[ifd][tag]["name"] if tag in piexif.TAGS[ifd].keys() else tag
                result[tag_name] = _exif[ifd][tag].decode('utf-8') if isinstance(_exif[ifd][tag], bytes) else _exif[ifd][tag]

        return result
