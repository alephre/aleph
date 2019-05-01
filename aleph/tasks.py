import logging

from aleph import app
from aleph.config import settings
from aleph.config.constants import COMPONENT_TYPE_PROCESSOR, COMPONENT_TYPE_ANALYZER
from aleph.common.loader import list_submodules
from aleph.common.utils import decode_data, hash_data, get_plugin, call_task
from aleph.helpers.classifiers import detect_filetype
from aleph.common.exceptions import AnalyzerSetupException, AnalyzerRuntimeException, ProcessorSetupException, ProcessorRuntimeException

@app.task(bind=True)
def analyze(self, sample):

    self.logger.info('Sending sample %s for analysis' % sample['id'])
    try:
        dispatch(COMPONENT_TYPE_ANALYZER, sample)
    except AnalyzerSetupException as e:
        self.logger.error("Error initializing analyzer: %s" % e.get_exception_text())
    except AnalyzerRuntimeException as e:
        self.logger.error("Error running analyzer: %s" % e.get_exception_text())
    except Exception as e:
        self.logger.error("Unhandled exception on analyze task: %s" % str(e))
        raise e


@app.task(bind=True)
def process(self, sample_data, metadata):

    # Grab additional metadata
    binary_data = decode_data(sample_data)
    sample_id = hash_data(binary_data)

    self.logger.info("Recieved sample %s for processing" % sample_id)

    # Autodetect filetype if not provided
    if 'filetype' not in metadata.keys():
        metadata['filetype'], metadata['filetype_desc'] = detect_filetype(binary_data)

    metadata['size'] = len(binary_data)

    # Store sample
    call_task('aleph.storages.tasks.store', args=[sample_id, sample_data])
    self.logger.info("Sample %s sent to storage" % sample_id)

    # Prepare and send to processing pipeline
    sample = {
        'id': sample_id,
        'data': sample_data,
        'metadata': metadata,
    }

    try:
        dispatch(COMPONENT_TYPE_PROCESSOR, sample)
    except ProcessorSetupException as e:
        self.logger.error("Error initializing processor: %s" % e.get_exception_text())
    except ProcessorRuntimeException as e:
        self.logger.error("Error running processor: %s" % e.get_exception_text())
    except Exception as e:
        self.logger.error("Unhandled exception on process task: %s" % str(e))

def dispatch(component_type, sample):

    if component_type not in [COMPONENT_TYPE_PROCESSOR, COMPONENT_TYPE_ANALYZER]:
        raise ValueError("Invalid component type: %s" % component_type)

    logger = logging.getLogger(__name__)

    sample_id = sample['id'] 

    plugins = list_submodules('aleph.%ss' % component_type)

    plugins_dispatched = []

    metadata = sample['metadata']

    for loader, plugin_name, is_pkg in plugins:

        if plugin_name.startswith('tasks'):
            continue

        try:
            plugin = get_plugin(component_type, plugin_name)(dry=True)
        except Exception as e:
            if component_type is COMPONENT_TYPE_PROCESSOR:
                raise ProcessorSetupException(e)
            elif component_type is COMPONENT_TYPE_ANALYZER:
                raise AnalyzerSetupException(e)

        try:
            if not plugin.can_act(sample):
                continue

            routing_key = 'plugins.%s' % plugin.category
            call_task('aleph.%ss.tasks.run' % component_type, args=[plugin_name, sample], routing_key=routing_key)

        except Exception as e:
            if component_type is COMPONENT_TYPE_PROCESSOR:
                raise ProcessorRuntimeException(e)
            elif component_type is COMPONENT_TYPE_ANALYZER:
                raise AnalyzerRuntimeException(e)

        plugins_dispatched.append(plugin.name)

    # Track dispatched plugins
    metadata['%ss_dispatched' % component_type] = plugins_dispatched

    # Create datastore entry
    call_task('aleph.datastores.tasks.store', args=[sample_id, metadata])
