import os
import ntpath
import shutil

from tempfile import mkdtemp
from io import BytesIO
from aleph.base import ProcessorBase

class ArchiveProcessor(ProcessorBase):

    default_options = { 'enabled': False, }

    engine = None
    namelist = 'namelist'
    mimetypes = ['none']

    def setup(self):
        raise NotImplementedError('Archive processor should not be run by itself. Child classes should implement the setup() method and set self.engine to the appropriate archive library and self.namelist to the list files function')

    def extract_file(self, src, dest, password=None, mimetype=None):

        with self.engine(src, 'r') as archive:
            if password:
                archive.setpassword(password)

            archive.extractall(dest)

            return getattr(archive, self.namelist)()

    def tag_archive(self):
        self.add_tag('archive')

    def process(self, sample):

        sample_data = sample['data']
        file_obj = BytesIO(sample_data)

        temp_dir = mkdtemp(prefix='aleph_')

        current_password = None
        
        total_passwords = self.options.get('passwords') if self.options.has_option('passwords') else []
        total_passwords.insert(0, None) # Append blank password

        archive_contents = []
        last_exception = None

        for password in total_passwords:

            current_password = password

            self.logger.debug("Uncompressing sample %s with password '%s'" % (sample['id'], password))
            try:
                archive_contents = self.extract_file(file_obj, temp_dir, password=password, mimetype=sample['metadata']['mimetype'])
                break
            except Exception as e:
                last_exception = str(e)
                continue # Invalid password
        
        extracted_files = []

        for fname in archive_contents:
            fpath = os.path.join(temp_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, 'rb') as fdata:
                    self.dispatch(fdata.read(), parent=sample['id'], filename=fname)
                extracted_files.append(fpath)

        # Cleanup temp dir
        shutil.rmtree(temp_dir)

        ret = {}

        # Add general tags
        self.tag_archive()

        if len(extracted_files) == 0:
            self.logger.error('Unable to uncompress sample %s [%s]: %s' % (
                sample['id'], 
                sample['metadata']['mimetype'],
                last_exception
                ))
            self.add_tag('archive-invalid')
            return ret

        ret['contents'] = archive_contents
        ret['extracted_files'] = extracted_files

        if set(archive_contents) is not set(extracted_files):
            self.add_tag('extraction-incomplete')

        if current_password:
            self.add_tag('password-protected')
            ret['password'] = current_password

        return ret
