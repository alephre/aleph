CELERY_AUTODISCOVER_TASKS = [
    'aleph',
    'aleph.collectors',
    'aleph.processors',
    'aleph.analyzers',
    'aleph.datastores',
    'aleph.storages',
]

FILETYPES_ARCHIVE = [
    'application/zip',
    'application/gzip',
    'application/x-gzip',
    'application/x-rar',
    'application/tar'
]

CLASSIFIER_YARA_DEFAULT_RULES = 'etc/filetypes.yara'
