from zipfile import ZipFile
from aleph.processors.archive import ArchiveProcessor

class ZipArchiveProcessor(ArchiveProcessor):

    name = 'ziparchive'
    default_options = { 'enabled': True, 'passwords': [ 'infected', 'evil', 'virus', 'malicious' ] }
    mimetypes = ['application/zip']

    def setup(self):
        self.engine = ZipFile

    def tag_archive(self):
        self.add_tag('archive')
        self.add_tag('zip')
