from kombu.common import Broadcast, Exchange, Queue

# Exchanges setup
plugins_generic = Exchange('plugins.generic', type='fanout')
plugins = Exchange('plugins', arguments={'alternate-exchange': 'plugins.generic'})

# Queues setup
task_queues = (
    Broadcast('collector'),
    Queue('plugins.generic', exchange=plugins_generic),
    Queue('plugins.windows', exchange=plugins, routing_key='plugins.windows'),
    Queue('plugins.linux', exchange=plugins, routing_key='plugins.linux'),
    Queue('plugins.macos', exchange=plugins, routing_key='plugins.macos'),
    Queue('plugins.sandbox', exchange=plugins, routing_key='plugins.sandbox'),
    Queue('manager'),
    Queue('store'),
    )
# Celery Routing
task_routes = ([
    ('aleph.collectors.tasks.collect', {'queue': 'collector'}),
    ('aleph.collectors.tasks.ingest', {'queue': 'collector'}),
    ('aleph.storages.tasks.store', {'queue': 'store'}),
    ('aleph.datastores.tasks.store', {'queue': 'store'}),
    ('aleph.datastores.tasks.update_task_states', {'queue': 'store'}),
    ('aleph.tasks.process', {'queue': 'manager'}),
    ('aleph.tasks.run_plugin', {'exchange': plugins}),
],)

# Celery Beat
beat_schedule = {
    'collectors-broadcast-collect': { 'task': 'aleph.collectors.tasks.collect', 'schedule': 10.0, },
    'collectors-broadcast-collect': { 'task': 'aleph.datastores.tasks.update_task_states', 'schedule': 10.0, },
}

