from aleph import app, settings
from aleph.loader import load_datastore
from aleph.base import TaskBase


DATASTORES = [(name, load_datastore(name)(options)) for name, options in settings.get('datastore').items()]

@app.task(bind=True, base=TaskBase)
def update_task_states(self):

    for name, datastore in DATASTORES:
        self.logger.info("Calling 'update_task_states' on %s datastore" % name)
        datastore.update_task_states()

    self.logger.debug("'update_task_states' completed on all datastores")

@app.task(bind=True, base=TaskBase)
def store(self, sample_id, metadata):

    for name, datastore in DATASTORES:
        self.logger.info("Storing metadata for %s on datastore" % sample_id)
        datastore.store(sample_id, metadata)
        self.logger.debug("Metadata for %s stored on datastore" % sample_id)

    self.logger.debug("Datastore storage routine finished")
