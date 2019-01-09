import os
import json

from aleph import settings, logger
from aleph.utils import ConfigManager, hash_data, encode_data, decode_data, get_filetype

class PluginBase(object):

    name = None

    options = {}
    category = 'generic'
    default_options = {
        'enabled': True,
    }
    required_options = []

    mimetypes = []
    mimetypes_exclude = []

    engine = None

    document_meta = {}

    def __init__(self, options = None):

        super(PluginBase, self).__init__()

        if not self.name:
            self.name = self.__class__.__name__.lower()[:-6]

        if not options:
            if settings.has_option('plugins'):
                self.options = ConfigManager(config=settings.get('plugins'), section_name = self.name)
            else:
                self.options = ConfigManager()
        else:
            self.options = ConfigManager(config=options)

        for option, value in self.default_options.items():
            if not self.options.has_option(option):
                self.options.set(option, value)

        try:
            self.validate_options()
            self.setup()
        except Exception as e:
            logger.error('Error starting plugin %s: %s' % (self.__class__.__name__, str(e)))

    def validate_options(self):
        for option in self.required_options:
            if not self.options.has_option(option):
                raise KeyError('Required option "%s" not defined for %s plugin' % (option, self.name))
    def add_tag(self, tag):
        if not 'tags' in self.document_meta:
            self.document_meta['tags'] = []
        self.document_meta['tags'].append(tag)
    
    def setup(self):
        pass

    def process(self, sample_data):
        raise NotImplementedError('Process routine not implemented on %s plugin' % self.name)

class DatastoreBase(object):

    name = None

    options = {}
    default_options = {}
    required_options = []

    engine = None

    def __init__(self, options = None):

        super(DatastoreBase, self).__init__()

        if not self.name:
            self.name = self.__class__.__name__.lower()[:-9]

        if not options:
            if settings.has_option('datastores'):
                self.options = ConfigManager(config=settings.get('datastores'), section_name = self.name)
            else:
                self.options = ConfigManager()
        else:
            self.options = ConfigManager(config=options)

        for option, value in self.default_options.items():
            if not self.options.has_option(option):
                self.options.set(option, value)

        try:
            self.validate_options()
            self.setup()
        except Exception as e:
            logger.error('Error starting datastore handler %s: %s' % (self.__class__.__name__, str(e)))

    def validate_options(self):
        for option in self.required_options:
            if not self.options.has_option(option):
                raise KeyError('Required option "%s" not defined for %s datastore handler' % (option, self.name))

    def setup(self):
        pass

    def retrieve(self, sample_id):
        raise NotImplementedError('Retrieve routine not implemented on %s datastore handler' % self.name)

    def store(self, sample_id, document):
        raise NotImplementedError('Store routine not implemented on %s datastore handler' % self.name)

    def update(self, sample_id, document):
        raise NotImplementedError('Store routine not implemented on %s datastore handler' % self.name)

class StorageBase(object):

    name = None

    options = {}
    default_options = {}
    required_options = []

    def __init__(self, options = None):

        super(StorageBase, self).__init__()

        if not self.name:
            self.name = self.__class__.__name__.lower()[:-9]

        if not options:
            if settings.has_option('stroages'):
                self.options = ConfigManager(config=settings.get('storages'), section_name = self.name)
            else:
                self.options = ConfigManager()
        else:
            self.options = ConfigManager(config=options)

        for option, value in self.default_options.items():
            if not self.options.has_option(option):
                self.options.set(option, value)

        try:
            self.validate_options()
            self.setup()
        except Exception as e:
            logger.error('Error starting storage handler %s: %s' % (self.__class__.__name__, str(e)))

    def validate_options(self):
        for option in self.required_options:
            if not self.options.has_option(option):
                raise KeyError('Required option "%s" not defined for %s storage handler' % (option, self.name))

    def encode(self, data):
        return encode_data(data)

    def decode(self, data):
        return decode_data(data)

    def setup(self):
        pass

    def retrieve(self, sample_id):
        raise NotImplementedError('Retrieve routine not implemented on %s storage handler' % self.name)

    def store(self, sample_id, data):
        raise NotImplementedError('Store routine not implemented on %s storage handler' % self.name)

class CollectorBase(object):

    name = None

    options = {}
    default_options = {}
    required_options = []

    def __init__(self, options = None):

        super(CollectorBase, self).__init__()

        if not self.name:
            self.name = self.__class__.__name__.lower()[:-9]

        if not options:
            if settings.has_option('stroages'):
                self.options = ConfigManager(config=settings.get('storages'), section_name = self.name)
            else:
                self.options = ConfigManager()
        else:
            self.options = ConfigManager(config=options)

        for option, value in self.default_options.items():
            if not self.options.has_option(option):
                self.options.set(option, value)

        try:
            self.validate_options()
            self.setup()
        except Exception as e:
            logger.error('Error starting collector %s: %s' % (self.__class__.__name__, str(e)))

    def validate_options(self):
        for option in self.required_options:
            if not self.options.has_option(option):
                raise KeyError('Required option "%s" not defined for %s collector' % (option, self.name))

    def setup(self):
        pass

    def collect(self):
        raise NotImplementedError('Collection routine not implemented on %s collector' % self.name)

    def store(self, data, metadata={}):
       
        sample_id = hash_data(data)

        metadata['mimetype'], metadata['mimetype_str'] = get_filetype(data)
        metadata['size'] = len(data)

        root_path = settings.get('relay_folder')

        file_path = os.path.join(root_path, '%s.sample' % sample_id)
        metadata_path = os.path.join(root_path, '%s.json' % sample_id)

        logger.debug("Storing local data for %s" % sample_id)
        with open(file_path, 'wb') as f_out:
            f_out.write(data)
        logger.debug("Data for %s stored at %s" % (sample_id, file_path))

        logger.debug("Storing metadata for %s" % sample_id)
        with open(metadata_path, 'w') as m_out:
            m_out.write(json.dumps(metadata))
        logger.debug("Metadata for %s stored at %s" % (sample_id, metadata_path))
