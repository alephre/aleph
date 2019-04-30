from slugify import slugify 
from urllib.parse import urlparse

from aleph.common.base import Processor

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

        self.extract_domain_sample(url_object.netloc, sample['id'])

        return metadata

    def extract_domain_sample(self, domain, parent_id):

        metadata = {
            'filetype': 'meta/domain',
            'filetype_desc': 'domain extracted from url'
        }
        filename = '%s.domain.meta' % slugify(domain).lower()
        filedata = bytes(domain, 'utf-8')

        self.dispatch(filedata, metadata=metadata, filename=filename, parent=parent_id)

