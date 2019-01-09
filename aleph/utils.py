import yaml
import pkgutil
import sys
import inspect
import importlib
import magic

from hashlib import sha256
from base64 import b64encode, b64decode

def hash_data(data, algo=sha256):
    hasher = algo()
    hasher.update(data)
    return hasher.hexdigest()

def encode_data(data):
    return b64encode(data).decode('utf-8')

def decode_data(data):
    return b64decode(data.encode('utf-8'))

# Config Manager
class ConfigManager(object):

    config = {}
    section_name = None

    def __init__(self, config = {}, section_name = None):
        self.config = config
        self.section_name = section_name

    def base(self):
        return self.config[self.section_name] if self.section_name and self.section_name in self.config.keys() else self.config

    def load(self, path):
        with open(path) as f:
            self.config = yaml.safe_load(f)

    def dump(self):
        return self.config

    def get(self, option):
        if self.has_option(option):
            return self.base()[option]
        return None

    def set(self, option, value):
        self.base()[option] = value

    def has_option(self, option):
        return (option in self.base())

def load_component(component_name, package_name, component_type):

    try:

        module_name = 'aleph.%s.%s_%s'  % (package_name.lower(), component_name.lower(), component_type.lower())
        class_name = None
        
        #@FIXME @jseidl can we check if we can have this persist? or check if its already loaded?
        module = importlib.import_module(module_name)
        
        class_members = inspect.getmembers(sys.modules[module_name], inspect.isclass)
        
        for name, obj in class_members:
            expected_name = '%s%s' % (component_name, component_type)
            if name.lower() == expected_name.lower():
                class_name = name
                break
        
        if not class_name:
            raise ImportError("No suitable class found for %s '%s'" % (component_type, component_name))
        
        component = getattr(module, class_name)
        
        return component

    except Exception as e:
        raise

def load_collector(name):
    return load_component(name, 'collectors', 'collector')

def load_storage(name):
    return load_component(name, 'storages', 'storage')

def load_datastore(name):
    return load_component(name, 'datastores', 'datastore')

def load_plugin(name):
    return load_component(name, 'plugins', 'plugin')

def list_submodules(package_name, namesOnly=False): 
    """ Lists all submodules of a module, recursively
    :param package_name: Package name
    :type package_name: str
    :rtype: list[str]
    """
    package = sys.modules[package_name]
    return pkgutil.walk_packages(package.__path__)

def import_submodules(package_name):
    """ Import all submodules of a module, recursively
    :param package_name: Package name
    :type package_name: str
    :rtype: dict[types.ModuleType]
    """

    try:
        return {
            name: importlib.import_module(package_name + '.' + name)
            for loader, name, is_pkg in list_submodules(package_name)
            }
    except ImportError as ex:
        raise

def get_filetype(data):

    return (
        magic.from_buffer(data, mime=True),
        magic.from_buffer(data),
    )

def in_string(tokens, string):
    return any(token in str(string).lower() for token in tokens)  
