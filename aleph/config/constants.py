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

GEOLOCATION_DATABASE_PATH = 'etc/geolocation'
GEOLOCATION_DATABASE_ASN = 'GeoLite2-ASN.mmdb'
GEOLOCATION_DATABASE_CITY = 'GeoLite2-City.mmdb'

COMPONENT_TYPE_ANALYZER = 'analyzer'
COMPONENT_TYPE_PROCESSOR = 'processor'

FIELD_SAMPLE_ID = 'id'
FIELD_SAMPLE_DATA = 'data'
FIELD_SAMPLE_METADATA = 'metadata'
FIELD_SAMPLE_INTERNAL = 'control'
FIELD_SAMPLE_FILETYPE = 'filetype'
FIELD_SAMPLE_FILETYPE_DESC = 'filetype_desc'
FIELD_SAMPLE_SIZE = 'size'
FIELD_SAMPLE_PROCESSOR_ITEMS = 'artifacts'
FIELD_SAMPLE_ANALYZER_ITEMS = 'flags'
FIELD_SAMPLE_TIMESTAMP = 'timestamp'
FIELD_SAMPLE_IOCS = 'iocs'

FIELD_TRACK_TAGS = 'tags'
FIELD_TRACK_KNOWN_FILENAMES = 'known_filenames'
FIELD_TRACK_PARENTS = 'parents'
FIELD_TRACK_PLUGIN_DISPATCHED = '%ss_dispatched'
FIELD_TRACK_PLUGIN_COMPLETED = '%ss_completed'

CACHE_LRU_SIZE = 32

ASCII_ART_ALEPH_LOGOS = ["""

          @@
         @@@@           aleph | sample analysis pipeline
        @@  @@          https://aleph.re
       @@    @@
      @@      @@        Version: %s
     @@        @@
    @@          @@
   @@            @@     Dissecting files for better threat intelligence since 2012
  @@              @@
 @@  @@@@@@@@@@@@@@@@

""",
"""
      _       __                 __
     / \     [  |               [  |
    / _ \     | | .---.  _ .--.  | |--.
   / ___ \    | |/ /__\\[ '/'`\ \| .-. |
 _/ /   \ \_  | || \__., | \__/ || | | |
|____| |____|[___]'.__.' | ;.__/[___]|__]
                        [__|

  aleph | sample analysis pipeline
  version: %s

""",
"""

        https://aleph.re
         version: %s

 █████╗ ██╗     ███████╗██████╗ ██╗  ██╗
██╔══██╗██║     ██╔════╝██╔══██╗██║  ██║
███████║██║     █████╗  ██████╔╝███████║
██╔══██║██║     ██╔══╝  ██╔═══╝ ██╔══██║
██║  ██║███████╗███████╗██║     ██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝
  aleph | sample analysis pipeline
"""
]


