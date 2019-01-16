import os
import json
import logging

from datetime import datetime

from celery import Task
from celery.utils.log import get_task_logger

from aleph.config import ConfigManager, settings
from aleph.common.utils import encode_data, decode_data, call_task

class TaskBase(Task):

    def __call__(self, *args, **kwargs):
        self.logger = get_task_logger(__name__)
        return self.run(*args, **kwargs)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        self.logger.warning('Task %s[%s] is being queued for retry: %s' % (self.name, task_id, einfo))

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        self.logger.error('Task %s[%s] failed: %s' % (self.name, task_id, einfo))
        self.retry(exc=exc)

class ComponentBase(object):

    name = None
    options = {}
    default_options = {}
    required_options = []
    logger = None
    component_type = None

    def __init__(self, options = None, logger = None, dry=False):

        super(ComponentBase, self).__init__()

        if not self.component_type:
            raise NotImplementedError('component_type is undefined')

        # Configure Logger
        if not logger:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        # Auto-resolve name if not set
        if not self.name:
            self.name = self.__class__.__name__.lower().replace(self.component_type.lower(), '')

        # Configure Options
        if not options:
            config = {}
            if settings.has_option(self.component_type):
                component_settings = settings.get(self.component_type)
                if component_settings and self.name in component_settings.keys():
                    config = component_settings[self.name]
        else:
            config = options

        self.options = ConfigManager(config=config)

        for option, value in self.default_options.items():
            if not self.options.has_option(option):
                self.options.set(option, value)

        # Dry run, do not setup nor validate
        if dry:
            return 

        try:
            self.validate_options()
            self.init()
            self.setup()
        except Exception as e:
            self.logger.error('Error starting component %s: %s' % (self.__class__.__name__, str(e)))

    def validate_options(self):
        for option in self.required_options:
            if not self.options.has_option(option):
                raise KeyError('Required option "%s" not defined for %s handler' % (option, self.name))

    def dispatch(self, data, metadata={}, filename=None, parent=None, args=None):

        metadata['timestamp'] = datetime.utcnow().timestamp()

        metadata['sources'] = [{ 
                'worker': settings.get('worker_name'), 
                'component_type': self.component_type,
                'component_name': self.name, 
                'filename': filename,
                'parent': parent,
                'args': args,
            }]
       
        safe_data = encode_data(data)
        call_task('aleph.tasks.process', args=[safe_data, metadata])

    def setup(self):
        pass

    def init(self):
        pass

class PluginBase(ComponentBase):

    component_type = 'plugin'

    category = 'generic'
    default_options = { 'enabled': True, }

    mimetypes = []
    mimetypes_exclude = []

    document_meta = {}

    def can_act(self, sample):

        if not self.options.get('enabled'):
            return False

        # Check for mimetype-specific plugins
        mimetype = sample['metadata']['mimetype']
        if len(self.mimetypes) > 0:
            if not mimetype in self.mimetypes:
                return False

        if len(self.mimetypes_exclude) > 0:
            if mimetype in self.mimetypes_exclude:
                return False

        return True

    def add_tag(self, tag):
        if not 'tags' in self.document_meta:
            self.document_meta['tags'] = []
        self.document_meta['tags'].append(tag)
    
    def init(self):

        self.document_meta = {}

class ProcessorBase(PluginBase):

    component_type = 'processor'
    
    def process(self, sample):
        raise NotImplementedError('Process routine not implemented on %s plugin' % self.name)

class AnalyzerBase(PluginBase):

    component_type = 'analyzer'
    
    def process(self, sample):
        raise NotImplementedError('Process routine not implemented on %s plugin' % self.name)


class DatastoreBase(ComponentBase):

    component_type = 'datastore'
    default_options = { 'enabled': False, }
    engine = None

    def update_task_states(self):
        raise NotImplementedError('Update task states routine not implemented on %s datastore handler' % self.name)

    def retrieve(self, sample_id):
        raise NotImplementedError('Retrieve routine not implemented on %s datastore handler' % self.name)

    def store(self, sample_id, document):
        raise NotImplementedError('Store routine not implemented on %s datastore handler' % self.name)

    def update(self, sample_id, document):
        raise NotImplementedError('Store routine not implemented on %s datastore handler' % self.name)

    def dispatch(self, sample_id, metadata):

        sample = {
            'id': sample_id,
            'metadata': metadata,
        }
        call_task('aleph.tasks.analyze', args=[sample])

class StorageBase(ComponentBase):

    component_type = 'storage'
    default_options = { 'enabled': False, }

    def encode(self, data):
        return encode_data(data)

    def decode(self, data):
        return decode_data(data)

    def retrieve(self, sample_id):
        raise NotImplementedError('Retrieve routine not implemented on %s storage handler' % self.name)

    def store(self, sample_id, data):
        raise NotImplementedError('Store routine not implemented on %s storage handler' % self.name)

class CollectorBase(ComponentBase):

    component_type = 'collector'
    default_options = { 'enabled': False, }

    def collect(self):
        raise NotImplementedError('Collection routine not implemented on %s collector' % self.name)
