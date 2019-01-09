from celery.utils.log import get_task_logger

from aleph import app, settings
from aleph.utils import load_plugin, list_submodules, decode_data

logger = get_task_logger(__name__)

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def process(sample):

    logger.debug('Dispatching %s to suitable plugins' % sample['id'])

    plugins = list_submodules('aleph.plugins', namesOnly=True)

    for loader, name, is_pkg in plugins:

        plugin_name = name.split('_')[0]
        plugin = load_plugin(plugin_name)(dry=True)

        if not plugin.can_act(sample):
            continue

        routing_key = 'plugins.%s' % plugin.category
        logger.debug("Dispatching %s to plugin %s" % (sample['id'], plugin_name))
        run_plugin.apply_async((plugin_name, sample), routing_key=routing_key)

@app.task(autoretry_for=(Exception,), retry_backoff=True)
def run_plugin(plugin_name, sample):

    logger.debug("Received sample %s for plugin %s" % (sample['id'], plugin_name))

    logger.debug("Loading %s plugin" % plugin_name)
    plugin = load_plugin(plugin_name)()

    sample['data'] = decode_data(sample['data'])

    logger.debug("Running %s plugin" % plugin_name)
    result = plugin.process(sample)

    metadata = {plugin.name: result}

    # Add tags to main document metadata
    if 'tags' in plugin.document_meta:
        metadata['tags'] = plugin.document_meta['tags']

    # Send metadata to datastore
    logger.debug("Sending %s plugin metadata for sample %s to datastores" % (plugin.name, sample['id']))
    app.send_task('aleph.datastores.tasks.store', args=[sample['id'], metadata])

    logger.debug("Execution completed for %s plugin" % plugin.name)
