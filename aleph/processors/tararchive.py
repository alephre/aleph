import tarfile
from aleph.processors.archive import Archive

class TarArchive(Archive):

    name = 'tararchive'
    default_options = { 'enabled': True, }
    filetypes = [
        'application/x-tar', 
        'application/gzip', 
        'application/x-gzip',
        'application/x-xz',
        'application/x-bzip2',
        ]

    mode = ''

    def setup(self):
        pass

    def extract_file(self, src, dest, password=None, filetype=None):

        _mode = {
            'application/x-tar': '', 
            'application/gzip': 'gz', 
            'application/x-gzip': 'gz',
            'application/x-xz': 'xz',
            'application/x-bzip2': 'bz2'
        }.get(filetype)

        self.mode = _mode

        with tarfile.open(fileobj=src, mode='r:%s' % _mode) as tarf:
            tarf.extractall(dest)
            return tarf.getnames()

    def tag_archive(self):
        self.add_tag('archive')
        if self.mode:
            self.add_tag('tar-%s' % self.mode)
        else:
            self.add_tag('tar')
