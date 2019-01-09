from aleph import app, logger
from aleph.utils import load_plugin, import_submodules, decode_data

@app.task
def process(sample_id, sample_data, mimetype):

    logger.debug('Dispatching %s to suitable plugins' % sample_id)
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

@app.task
def run_plugin(plugin_name, sample_id, sample_data):
    logger.debug("Received sample %s for plugin %s" % (sample_id, plugin_name))
    # Run plugin & get extracted data
    logger.debug("Loading %s plugin" % plugin_name)
    plugin = load_plugin(plugin_name)()
    logger.debug("Running %s plugin" % plugin_name)
    binary_data = decode_data(sample_data)
    result = plugin.process(binary_data)
    # Send metadata to datastore
    metadata = {plugin.name: result}
    logger.debug("Sending %s plugin metadata for sample %s to datastores" % (plugin_name, sample_id))
    app.send_task('aleph.datastores.tasks.store', args=[sample_id, metadata])
    logger.debug("Execution completed for %s plugin" % plugin_name)
