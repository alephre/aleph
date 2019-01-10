from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.utils import load_plugin, list_submodules, decode_data, hash_data, get_filetype

logger = get_task_logger(__name__)

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

    logger.debug('Dispatching %s to suitable plugins' % sample['id'])

    plugins = list_submodules('aleph.plugins', namesOnly=True)

    plugins_dispatched = []

    for loader, name, is_pkg in plugins:

        plugin_name = name.split('_')[0]
        plugin = load_plugin(plugin_name)(dry=True)

        if not plugin.can_act(sample):
            continue

        routing_key = 'plugins.%s' % plugin.category
        logger.debug("Dispatching %s to plugin %s" % (sample['id'], plugin_name))
        run_plugin.apply_async((plugin_name, sample), routing_key=routing_key)

        plugins_dispatched.append(plugin.name)

    # Track dispatched plugins
    metadata['plugins_dispatched'] = plugins_dispatched

    # Create datastore entry
    app.send_task('aleph.datastores.tasks.store', args=[sample['id'], metadata])
    logger.debug("Sample %s sent to datastore" % sample_id)

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def run_plugin(plugin_name, sample):

    logger.debug("Received sample %s for plugin %s" % (sample['id'], plugin_name))

    logger.debug("Loading %s plugin" % plugin_name)
    plugin = load_plugin(plugin_name)()

    sample['data'] = decode_data(sample['data'])

    logger.debug("Running %s plugin" % plugin_name)
    result = plugin.process(sample)

    metadata = {}
    metadata['artifacts'] = {plugin.name: result}

    # Add tags to main document metadata
    if 'tags' in plugin.document_meta:
        metadata['tags'] = plugin.document_meta['tags']

    # Add current plugin to metadata
    metadata['plugins_completed'] = [plugin.name,]

    # Send metadata to datastore
    logger.debug("Sending %s plugin metadata for sample %s to datastores" % (plugin.name, sample['id']))
    app.send_task('aleph.datastores.tasks.store', args=[sample['id'], metadata])

    logger.debug("Execution completed for %s plugin" % plugin.name)
