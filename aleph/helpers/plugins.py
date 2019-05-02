from celery.utils.log import get_task_logger

from aleph.config.constants import COMPONENT_TYPE_ANALYZER, COMPONENT_TYPE_PROCESSOR
from aleph.config.constants import FIELD_SAMPLE_PROCESSOR_ITEMS, FIELD_SAMPLE_ANALYZER_ITEMS, FIELD_SAMPLE_ID, FIELD_SAMPLE_DATA
from aleph.config.constants import FIELD_TRACK_TAGS, FIELD_TRACK_PLUGIN_COMPLETED 
from aleph.exceptions import ProcessorSetupException, ProcessorRuntimeException
from aleph.helpers.datautils import decode_data
from aleph.helpers.loaders import load_processor, load_analyzer
from aleph.helpers.tasks import call_task

logger = get_task_logger(__name__)

PLUGIN_CACHE = {}

def get_plugin(component_type, plugin_name):

    if component_type not in [COMPONENT_TYPE_ANALYZER, COMPONENT_TYPE_PROCESSOR]:
        raise ValueError('Invalid component')

    module_name = '%s_%s' % (plugin_name, component_type)

    if module_name in PLUGIN_CACHE:
        logger.debug('Loading %s plugin from cache' % module_name)
        return PLUGIN_CACHE[module_name]

    components = {
        COMPONENT_TYPE_PROCESSOR: load_processor,
        COMPONENT_TYPE_ANALYZER: load_analyzer,
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
        sample_id = args[FIELD_SAMPLE_ID]

        if not sample_id:
            raise AttributeError('Sample id not defined in args')

        plugin = get_plugin(component_type, plugin_name)()

        if FIELD_SAMPLE_DATA in args:
            args[FIELD_SAMPLE_DATA] = decode_data(args[FIELD_SAMPLE_DATA])
    except Exception as e:
        raise ProcessorSetupException(e)

    try:
        logger.debug("Running %s plugin" % plugin_name)
        result = plugin.process(args)
    except Exception as e:
        raise ProcessorRuntimeException(e)

    metadata = {}
    track_data = {}

    if component_type == COMPONENT_TYPE_PROCESSOR:
        component_key = FIELD_SAMPLE_PROCESSOR_ITEMS
    elif component_type == COMPONENT_TYPE_ANALYZER:
        component_key = FIELD_SAMPLE_ANALYZER_ITEMS
    else:
        raise AttributeError('Invalid component type %s' % component_type)

    metadata[component_key] = {plugin.name: result}

    # Add tags to main document metadata
    if FIELD_TRACK_TAGS in plugin.document_meta:
        track_data[FIELD_TRACK_TAGS] = plugin.document_meta[FIELD_TRACK_TAGS]

    # Add current plugin to metadata
    track_data[FIELD_TRACK_PLUGIN_COMPLETED % component_type] = [plugin.name,]

    # Send metadata and track data to datastore
    logger.debug("Sending %s %s metadata for sample %s to datastores" % (plugin.name, component_type, sample_id))
    call_task('aleph.datastores.tasks.store', args=[sample_id, metadata])
    #@FIXME make atomic store and track
    call_task('aleph.datastores.tasks.track', args=[sample_id, track_data])

    logger.debug("Execution completed for %s plugin" % plugin.name)


