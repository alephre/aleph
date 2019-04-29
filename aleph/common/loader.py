import sys
import inspect
import importlib
import pkgutil

def load_component(component_name, package_name):

    if component_name == 'tasks':
        raise ImportError('Cannot import tasks module as a component')

    try:

        module_name = 'aleph.%s.%s'  % (package_name.lower(), component_name.lower())
        class_name = None
        
        module = importlib.import_module(module_name)
        
        class_members = inspect.getmembers(sys.modules[module_name], inspect.isclass)
        
        for name, obj in class_members:
            expected_name = '%s' % component_name
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
    return load_component(name, 'collectors')

def load_storage(name):
    return load_component(name, 'storages')

def load_datastore(name):
    return load_component(name, 'datastores')

def load_processor(name):
    return load_component(name, 'processors')

def load_analyzer(name):
    return load_component(name, 'analyzers')

def list_submodules(package_name): 
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
