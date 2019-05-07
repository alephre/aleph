from urllib.parse import urlparse

from aleph.models import Processor

class URL(Processor):

    filetypes = ['meta/url']

    def process(self, sample):

        sample_data = sample['data']
        ascii_data = sample_data.decode("utf-8")

        if not ascii_data.startswith('http'):
            ascii_data = '//%s' % ascii_data

        url_object = urlparse(ascii_data)

        metadata = {
            'full_url': ascii_data,
            'scheme': url_object.scheme,
            'netloc': url_object.netloc,
            'path': url_object.path,
            'params': url_object.params,
            'fragment': url_object.fragment,
            'username': url_object.username,
            'password': url_object.password,
            'port': url_object.port,
        }

        self.extract_meta_sample('domain', url_object.netloc, sample['id'])

        return metadata
