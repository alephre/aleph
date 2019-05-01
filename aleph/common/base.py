import os
import json
import logging

from datetime import datetime

from celery import Task
from celery.utils.log import get_task_logger

from abc import ABC

from aleph.config import ConfigManager, settings
from aleph.common.utils import encode_data, decode_data, call_task, to_es_date
from aleph.common.exceptions import PluginException

class AlephTask(Task):

    def __call__(self, *args, **kwargs):
        self.logger = get_task_logger(__name__)
        return self.run(*args, **kwargs)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        self.logger.info('Task %s[%s] is being queued for retry: %s' % (self.name, task_id, einfo))

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        self.logger.error('Task %s[%s] failed: %s' % (self.name, task_id, einfo))
        #self.retry(exc=exc)

class Component(ABC):

    name = None
    options = {}
    default_options = {}
    required_options = []
    logger = None
    component_type = None

    def __init__(self, options = None, logger = None, dry=False):

        super(Component, self).__init__()

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

    def dispatch(self, data, metadata={}, filename=None, parent=None):

        metadata['timestamp'] = to_es_date(datetime.utcnow())

        metadata['known_filenames'] = [filename,]
        metadata['parents'] = [parent,]
       
        safe_data = encode_data(data)
        call_task('aleph.tasks.process', args=[safe_data, metadata])

    def setup(self):
        pass

    def init(self):
        pass

class Plugin(Component):

    component_type = 'plugin'

    category = 'generic'
    default_options = { 'enabled': True, }

    filetypes = []
    filetypes_exclude = []

    document_meta = {}

    def can_act(self, sample):

        if not self.options.get('enabled'):
            return False

        if 'metadata' not in sample.keys() or not sample['metadata']:
            raise PluginException('Metadata not present for sample %s' % sample['id'])

        if 'filetype' not in sample['metadata']:
            raise PluginException('File type not present on sample %s' % sample['id'])

        # Check for filetype-specific plugins
        filetype = sample['metadata']['filetype']
        if len(self.filetypes) > 0:
            if not filetype in self.filetypes:
                return False

        if len(self.filetypes_exclude) > 0:
            if filetype in self.filetypes_exclude:
                return False

        return True

    def add_tag(self, tag):
        if not 'tags' in self.document_meta:
            self.document_meta['tags'] = []
        self.document_meta['tags'].append(tag)
    
    def init(self):

        self.document_meta = {}

class Processor(Plugin):

    component_type = 'processor'
    
    def process(self, sample):
        raise NotImplementedError('Process routine not implemented on %s plugin' % self.name)

class Analyzer(Plugin):

    component_type = 'analyzer'

    weights = {'info': 1, 'uncommon': 2, 'suspicious': 4, 'malicious': 8}

    sample = None

    flags = []
    indicators = []
    artifacts = {}

    def setup(self):

        self.flags = []
        self.indicators = []
        self.artifacts = {}

    def add_indicator(self, indicator):
        self.indicators.append(indicator)

    def has_indicator(self, indicator):
        return indicator in self.indicators

    def has_indicators(self, indicators):
        return set(indicators).issubset(self.indicators)
    
    def add_flag(self, flag_title, flag_text, category, severity, evil_rating = None, mitre_attack_id = []):

        if severity not in self.weights.keys():
            raise KeyError('Invalid severity: %s' % severity)

        if not isinstance(mitre_attack_id, list):
            raise ValueError('MITRE ATT&CK IDs must be supplied in a list')

        flag = {
            'title': flag_title,
            'text': flag_text,
            'category': category,
            'severity': severity,
            'evil_rating': evil_rating if evil_rating else self.weights[severity],
            'mitre_attack_id': mitre_attack_id
        }

        self.flags.append(flag)

    def analyze(self):
        raise NotImplementedError('Process routine not implemented on %s plugin' % self.name)

    def load(self, sample):

        if 'metadata' not in sample.keys():
            raise KeyError('Sample does not have metadatra')

        if 'artifacts' not in sample['metadata']:
            raise KeyError('Sample artifacts not present in metadata')

        self.sample = sample
        self.artifacts = self.sample['metadata']['artifacts']

    def process(self, sample):

        self.load(sample)
        self.analyze()
        return self.flags

class Datastore(Component):

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

class Storage(Component):

    component_type = 'storage'
    default_options = { 'enabled': False, }

    engine = None

    def retrieve(self, sample_id):
        raise NotImplementedError('Retrieve routine not implemented on %s storage handler' % self.name)

    def store(self, sample_id, data):
        raise NotImplementedError('Store routine not implemented on %s storage handler' % self.name)

class Collector(Component):

    component_type = 'collector'
    default_options = { 'enabled': False, }

    engine = None

    def collect(self):
        raise NotImplementedError('Collection routine not implemented on %s collector' % self.name)

class Classifier(Component):

    component_type = 'classifier'

    def detect(self, sample):
        raise NotImplementedError('Detect routine not implemented on %s filter' % self.name)

