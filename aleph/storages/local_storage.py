import os

from aleph.base import StorageBase

class LocalStorage(StorageBase):

    required_options = ['path']

    def validate_options(self):

        super(LocalStorage, self).validate_options()

        path = self.options.get('path')

        if not os.access(path, os.R_OK):
            try:
                os.mkdir(path)
                self.logger.info("Directory %s created" % path)
            except OSError as e:
                raise OSError("Unable to create storage directory at %s: %s" % (path, str(e)))

    def retrieve(self, sample_id):

        path = os.path.join(self.options.get('path'), '%s.sample' % sample_id)
        try:
            with open(path, 'rb') as f:
                data = f.read()
            return self.encode(data)
        except Exception as e:
            self.logger.error("Error retrieving sample %s: %s" % (sample_id, str(e)))
            return None

    def store(self, sample_id, data):

        path = os.path.join(self.options.get('path'), '%s.sample' % sample_id)
        try:
            binary_data = self.decode(data)
            with open(path, 'wb') as f:
                f.write(binary_data)
            return True
        except Exception as e:
            self.logger.error("Error storing sample %s: %s" % (sample_id, str(e)))
            return False
