import math
import re

from celery.utils.log import get_task_logger
from hashlib import sha256
from base64 import b64encode, b64decode
from collections import Counter

from aleph.common.exceptions import ProcessorSetupException, ProcessorRuntimeException
from aleph.common.loader import load_processor, load_analyzer

logger = get_task_logger(__name__)

PLUGIN_CACHE = {}

def hash_data(data, algo=sha256):
    hasher = algo()
    hasher.update(data)
    return hasher.hexdigest()

def encode_data(data):
    return b64encode(data).decode('utf-8')

def decode_data(data):
    return b64decode(data.encode('utf-8'))

def in_string(tokens, string):
    return any(token in str(string).lower() for token in tokens)  

def entropy(data):
    """Calculate the entropy of a chunk of data."""

    if len(data) == 0:
        return 0.0

    occurences = Counter(bytearray(data))

    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x*math.log(p_x, 2)

    return entropy

def normalize_name(name):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def get_plugin(component_type, plugin_name):

    module_name = '%s_%s' % (plugin_name, component_type)

    if module_name in PLUGIN_CACHE:
        logger.debug('Loading %s plugin from cache' % module_name)
        return PLUGIN_CACHE[module_name]

    components = {
        'processor': load_processor,
        'analyzer': load_analyzer,
    }

    loader = components.get(component_type, None)

    if not loader:
        raise ImportError("component %s (%s) not found" % (plugin_name, component_type))

    logger.debug('Loading %s plugin from disk' % module_name)

    try:
        PLUGIN_CACHE[module_name] = loader(plugin_name)
    except Exception as e:
        raise ImportError('Error importing module %s: %s' % (plugin_name, str(e)))

    return PLUGIN_CACHE[module_name]

def run_plugin(component_type, plugin_name, args):

    try:
        sample_id = args['id']

        if not sample_id:
            raise AttributeError('Sample id not defined in args')

        plugin = get_plugin(component_type, plugin_name)()

        if 'data' in args:
            args['data'] = decode_data(args['data'])
    except Exception as e:
        raise ProcessorSetupException(e)

    try:
        logger.debug("Running %s plugin" % plugin_name)
        result = plugin.process(args)
    except Exception as e:
        raise ProcessorRuntimeException(e)

    metadata = {}

    if component_type == 'processor':
        component_key = 'artifacts'
    elif component_type == 'analyzer':
        component_key = 'flags'
    else:
        raise AttributeError('Invalid component type %s' % component_type)

    metadata[component_key] = {plugin.name: result}

    # Add tags to main document metadata
    if 'tags' in plugin.document_meta:
        metadata['tags'] = plugin.document_meta['tags']

    # Add current plugin to metadata
    metadata['%ss_completed' % component_type] = [plugin.name,]

    # Send metadata to datastore
    logger.debug("Sending %s %s metadata for sample %s to datastores" % (plugin.name, component_type, sample_id))
    call_task('aleph.datastores.tasks.store', args=[sample_id, metadata])

    logger.debug("Execution completed for %s plugin" % plugin.name)

def call_task(task_name, args, routing_key='celery'):

    from aleph import app

    try:
        app.send_task(task_name, args=args, routing_key=routing_key)
    except Exception as e:
        logger.error("Error dispatching task %s: %s" % (task_name, str(e)))

def to_es_date(d):
    s = d.strftime('%Y-%m-%dT%H:%M:%S.')
    s += '%03d' % int(round(d.microsecond / 1000.0))
    s += d.strftime('%z')
    return s
