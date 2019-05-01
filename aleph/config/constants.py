CELERY_AUTODISCOVER_TASKS = [
    'aleph',
    'aleph.collectors',
    'aleph.processors',
    'aleph.analyzers',
    'aleph.datastores',
    'aleph.storages',
]

FILETYPES_META = [
    'meta/domain',
    'meta/url',
    'meta/host',
    'meta/location'
]

FILETYPES_ARCHIVE = [
    'application/zip',
    'application/gzip',
    'application/x-gzip',
    'application/x-rar',
    'application/tar'
]

CLASSIFIER_YARA_DEFAULT_RULES = 'etc/filetypes.yara'

COMPONENT_TYPE_ANALYZER = 'analyzer'
COMPONENT_TYPE_PROCESSOR = 'processor'
