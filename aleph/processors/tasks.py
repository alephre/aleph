from aleph import app
from aleph.helpers.plugins import run_plugin
from aleph.exceptions import BaseException


@app.task(bind=True)
def run(self, processor_name, sample):

    try:
        self.logger.info(
            "Applying processor %s on sample %s" % (processor_name, sample["id"])
        )
        run_plugin("processor", processor_name, sample)
    except BaseException as e:
        self.logger.error(
            "Error while running processor %s on sample %s: %s"
            % (processor_name, sample["id"], e.get_exception_text())
        )
    except Exception as e:
        self.logger.error(
            "Unhandled exception while running processor %s on sample %s: %s"
            % (processor_name, sample["id"], str(e))
        )
