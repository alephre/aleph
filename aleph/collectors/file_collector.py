import os

from aleph import settings
from aleph.base import CollectorBase

class FileCollector(CollectorBase):

    required_options = ['path']

    def validate_options(self):

        super(FileCollector, self).validate_options()

        path = self.options.get('path')

        if not os.access(path, os.R_OK):
            try:
                os.mkdir(path)
                self.logger.info("Directory %s created" % path)
            except OSError as e:
                raise OSError("Unable to create sample storage dir at %s: %s" % (path, str(e)))

    def collect(self):
        try:
            path = self.options.get('path')
            for dirname, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirname, filename)
                    if os.path.getsize(filepath) > 0:
                        self.logger.info("Collecting file %s from %s" % (filepath, path))
                        with open(filepath, 'rb') as f:

                            data = f.read()
                            metadata = {
                                'filename': [ filename ],
                                'source': [{ 
                                    'worker': settings.get('worker_name'), 
                                    'collector': self.name, 
                                    'path': filepath 
                                    }]
                            }

                            self.logger.debug("Inserting sample %s into the pipeline" % filepath)
                            self.dispatch(data, metadata=metadata)
                            self.logger.debug("Cleaning up file %s" % filepath)
                            os.remove(filepath)

        except Exception as e:
            pass
