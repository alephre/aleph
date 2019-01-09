from celery.utils.log import get_task_logger

from aleph import app
from aleph.utils import load_plugin, import_submodules, decode_data

logger = get_task_logger(__name__)

@app.task
def process(sample_id, sample_data, mimetype):

    logger.debug('Dispatching %s to suitable plugins' % sample_id)

    try:
        plugins = import_submodules('aleph.plugins')

        for plugin_name, plugin in plugins.items():

            short_name = plugin_name.split('_')[0]
            class_name = ''.join([word.capitalize() for word in plugin_name.split('_')])
            p = load_plugin(short_name)

            # Check for mimetype-specific plugins
            if len(p.mimetypes) > 0:
                if not mimetype in p.mimetypes:
                    continue
            if len(p.mimetypes_exclude) > 0:
                if mimetype in p.mimetypes_exclude:
                    continue

            logger.debug("Dispatching %s to plugin %s" % (sample_id, plugin_name))
            run_plugin.apply_async((short_name, sample_id, sample_data), routing_key='plugins.%s' % p.category)
    except Exception as e:
        logger.error('Error dispatching plugins for %s: %s' % (sample_id, str(e)))
        self.retry(exc=e)

@app.task
def run_plugin(plugin_name, sample_id, sample_data):

    logger.debug("Received sample %s for plugin %s" % (sample_id, plugin_name))
    try:

        logger.debug("Loading %s plugin" % plugin_name)
        plugin = load_plugin(plugin_name)()

        binary_data = decode_data(sample_data)

        logger.debug("Running %s plugin" % plugin_name)
        result = plugin.process(binary_data)

        metadata = {plugin.name: result}

        # Add tags to main document metadata
        if 'tags' in plugin.document_meta:
            metadata['tags'] = plugin.document_meta['tags']

        # Send metadata to datastore
        logger.debug("Sending %s plugin metadata for sample %s to datastores" % (plugin.name, sample_id))
        app.send_task('aleph.datastores.tasks.store', args=[sample_id, metadata])
    except Exception as e:
        logger.error('Error running plugin %s: %s' % (plugin.namme, str(e)))
        self.retry(exc=e)

    logger.debug("Execution completed for %s plugin" % plugin.name)
