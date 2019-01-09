import os
import json
import logging

from aleph import settings
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
    logger = None

    document_meta = {}

    def __init__(self, options = None, logger=None, dry=False):

        super(PluginBase, self).__init__()

        # Configure Logger
        if not logger:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        # Auto-resolve name if not set
        if not self.name:
            self.name = self.__class__.__name__.lower()[:-6]

        # Configure Options
        if not options:
            config = {}
            if settings.has_option('plugins'):
                plugins_settings = settings.get('plugins')
                if plugins_settings and self.name in plugins_settings.keys():
                    config = plugins_settings[self.name]
        else:
            config = options

        self.options = ConfigManager(config=config)

        for option, value in self.default_options.items():
            if not self.options.has_option(option):
                self.options.set(option, value)

        self.logger.debug("Plugin %s configured: %s" % (self.name, self.options.dump()))

        # Dry run, do not setup nor validate
        if dry:
            return 

        try:
            self.validate_options()
            self.setup()
            self.logger.debug("Plugin %s completely initialized" % self.name)
        except Exception as e:
            self.logger.error('Error starting plugin %s: %s' % (self.__class__.__name__, str(e)))

    def can_act(self, sample):

        if not self.options.get('enabled'):
            return False

        # Check for mimetype-specific plugins
        mimetype = sample['metadata']['mimetype']
        if len(self.mimetypes) > 0:
            if not mimetype in self.mimetypes:
                return False

        if len(self.mimetypes_exclude) > 0:
            if mimetype in p.mimetypes_exclude:
                return False

        return True

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
    logger = None

    def __init__(self, options = None, logger = None):

        super(DatastoreBase, self).__init__()

        # Configure Logger
        if not logger:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        # Auto-resolve name if not set
        if not self.name:
            self.name = self.__class__.__name__.lower()[:-9]

        # Configure options
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
            self.logger.error('Error starting datastore handler %s: %s' % (self.__class__.__name__, str(e)))

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

    logger = None

    def __init__(self, options = None, logger = None):

        super(StorageBase, self).__init__()

        # Configure Logger
        if not logger:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        # Auto-resolve name if not set
        if not self.name:
            self.name = self.__class__.__name__.lower()[:-9]

        # Configure options
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
            self.logger.error('Error starting storage handler %s: %s' % (self.__class__.__name__, str(e)))

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

    logger = None

    def __init__(self, options = None, logger = None):

        super(CollectorBase, self).__init__()

        # Configure Logger
        if not logger:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        # Auto-resolve name if not set
        if not self.name:
            self.name = self.__class__.__name__.lower()[:-9]
        
        # Configure options
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
            self.logger.error('Error starting collector %s: %s' % (self.__class__.__name__, str(e)))

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

        self.logger.debug("Storing local data for %s" % sample_id)
        with open(file_path, 'wb') as f_out:
            f_out.write(data)
        self.logger.debug("Data for %s stored at %s" % (sample_id, file_path))

        self.logger.debug("Storing metadata for %s" % sample_id)
        with open(metadata_path, 'w') as m_out:
            m_out.write(json.dumps(metadata))
        self.logger.debug("Metadata for %s stored at %s" % (sample_id, metadata_path))
