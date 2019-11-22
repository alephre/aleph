import os
from time import time

from aleph.models import Collector


class File(Collector):

    required_options = ["path"]

    def validate_options(self):

        super(File, self).validate_options()

        path = self.options.get("path")

        if not os.access(path, os.R_OK):
            try:
                os.mkdir(path)
                self.logger.info("Directory %s created" % path)
            except OSError as e:
                raise OSError(
                    "Unable to create sample storage dir at %s: %s" % (path, str(e))
                )

    def collect(self):
        try:
            path = self.options.get("path")
            for dirname, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirname, filename)

                    # Validate file for collection
                    if os.path.getsize(filepath) > 0 and os.access(filepath, os.R_OK):

                        # Prevent ingesting files that are still transfering
                        if self.options.has_option("mtime_grace") and (
                            time() - os.stat(filepath).st_mtime
                        ) < int(self.options.get("mtime_grace")):
                            self.logger.debug(
                                "File %s has been modified recently, prolly still transfering? Skipping until next collection round"
                                % filepath
                            )
                            continue

                        self.logger.info(
                            "Collecting file %s from %s" % (filepath, path)
                        )
                        with open(filepath, "rb") as f:

                            data = f.read()

                            self.logger.debug(
                                "Inserting sample %s into the pipeline" % filepath
                            )
                            self.dispatch(data, filename=filename)

                            self.logger.debug("Cleaning up file %s" % filepath)
                            os.remove(filepath)

        except IOError as e:
            self.logger.error("Error collecting file: %s" % str(e))
