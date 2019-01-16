import yaml

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
            print(self.config)

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


# Setup Aleph Settings
settings = ConfigManager()
settings.load('config.yaml')
