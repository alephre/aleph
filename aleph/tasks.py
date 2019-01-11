from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.loader import list_submodules
from aleph.utils import decode_data, hash_data, get_filetype, get_plugin

logger = get_task_logger(__name__)

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def analyze(sample):

    dispatch('analyzer', sample)

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def process(sample_data, metadata):

    # Grab additional metadata
    binary_data = decode_data(sample_data)
    sample_id = hash_data(binary_data)

    metadata['mimetype'], metadata['mimetype_str'] = get_filetype(binary_data)
    metadata['size'] = len(binary_data)

    # Store sample
    app.send_task('aleph.storages.tasks.store', args=[sample_id, sample_data])
    logger.debug("Sample %s sent to storage" % sample_id)

    # Prepare and send to processing pipeline
    sample = {
        'id': sample_id,
        'data': sample_data,
        'metadata': metadata,
    }

    dispatch('processor', sample)

def dispatch(component_type, sample):

    sample_id = sample['id'] 

    logger.debug('Dispatching %s to suitable %s' % (sample_id, component_type))

    plugins = list_submodules('aleph.%ss' % component_type)

    plugins_dispatched = []

    metadata = sample['metadata'] if 'data' in sample.keys() else {}

    for loader, name, is_pkg in plugins:

        plugin_name = name.split('_')[0]

        if plugin_name.startswith('tasks'):
            continue

        plugin = get_plugin(component_type, plugin_name)(dry=True)

        if not plugin.can_act(sample):
            continue

        routing_key = 'plugins.%s' % plugin.category
        logger.debug("Dispatching %s to %s %s" % (sample_id, component_type, plugin_name))
        app.send_task('aleph.%ss.tasks.run' % component_type, args=[plugin_name, sample], routing_key=routing_key)


        plugins_dispatched.append(plugin.name)

    # Track dispatched plugins
    metadata['%ss_dispatched' % component_type] = plugins_dispatched

    # Create datastore entry
    app.send_task('aleph.datastores.tasks.store', args=[sample_id, metadata])
    logger.debug("Sample %s sent to datastore" % sample_id)
