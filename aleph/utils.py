import magic

from celery.utils.log import get_task_logger
from hashlib import sha256
from base64 import b64encode, b64decode

from aleph import app
from aleph.loader import load_processor, load_analyzer

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

def get_filetype(data):

    #@TODO change to YARA with magic fallback. Yara results should be equal to magic's
    return (
        magic.from_buffer(data, mime=True),
        magic.from_buffer(data),
    )

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

    PLUGIN_CACHE[module_name] = loader(plugin_name)

    return PLUGIN_CACHE[module_name]

def run_plugin(component_type, plugin_name, args):

    sample_id = args['id']

    if not sample_id:
        raise AttributeError('Sample id not defined in args')

    plugin = get_plugin(component_type, plugin_name)()

    if 'data' in args:
        args['data'] = decode_data(args['data'])

    logger.debug("Running %s plugin" % plugin_name)
    result = plugin.process(args)

    metadata = {'artifacts': {}}
    metadata['artifacts'][component_type] = {plugin.name: result}

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
    try:
        app.send_task(task_name, args=args, routing_key=routing_key)
    except Exception as e:
        logger.error("Error dispatching task %s: %s" % (task_name, str(e)))
