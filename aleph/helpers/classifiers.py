import yara
import magic

from celery.utils.log import get_task_logger

from aleph.models import Classifier
from aleph.config.constants import CLASSIFIER_YARA_DEFAULT_RULES

logger = get_task_logger(__name__)


class Magic(Classifier):
    """Simple class to identfy magic type by file buffer."""

    def detect(self, data):
        try:
            return (magic.from_buffer(data, mime=True), magic.from_buffer(data))
        except Exception as err:
            logger.error("failed to get Magic MIME type. err={}".format(str(err)))

        return None


class Yara(Classifier):

    rules_file = CLASSIFIER_YARA_DEFAULT_RULES

    def setup(self):

        if self.options.has_option("rules_file"):
            self.rules_file = self.options.get("rules_file")

    def detect(self, data):
        """Identify file type by specialized Yara rule set where 'meta.file_type' stores abbreviated type names."""
        try:
            rules = yara.compile(self.rules_file)
        except Exception as err:
            logger.error(
                'YARA rules failed to compile" err="{0}" rules="{1}"'.format(
                    str(err), self.rules_file
                )
            )
            return None

        try:
            matches = rules.match(data=data)
        except Exception as err:
            logger.error(
                'YARA scan filed" err="{0}" rules="{1}"'.format(
                    str(err), self.rules_file
                )
            )
            return None

        for m in matches:
            if "file_type" in m.meta:
                return (m.meta["file_type"], m.meta["file_desc"])

        return None


def detect_filetype(data, engines=[Yara(), Magic()]):

    for e in engines:
        result = e.detect(data)
        if result:
            return result

    return (None, None)
