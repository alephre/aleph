import sys
import inspect
import importlib
import pkgutil

def load_component(component_name, package_name, component_type):

    try:

        module_name = 'aleph.%s.%s_%s'  % (package_name.lower(), component_name.lower(), component_type.lower())
        class_name = None
        
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
