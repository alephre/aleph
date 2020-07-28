import re

from aleph.config.constants import FILETYPES_ARCHIVE, FILETYPES_META
from aleph.exceptions import ProcessorRuntimeException
from aleph.helpers.iocs import find_iocs
from aleph.models import Processor

# String parsing functions from https://gist.github.com/williballenthin/8e3913358a7996eab9b96bd57fc59df2

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"


class Strings(Processor):

    name = "strings"
    filetypes_exclude = FILETYPES_ARCHIVE + FILETYPES_META + ["text/url"]

    default_options = {
        "extract_resources": True,
        "search_unicode": False,
        "min_str_len": 8,
        "iocs_exclude": [
            "ssdeeps",
            "phone_numbers",
            "email_addresses_complete",
            "ipv6s",
        ],
    }

    classifiers = {}

    def ascii_strings(self, buf, n=8):
        reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
        ascii_re = re.compile(reg)
        for match in ascii_re.finditer(buf):
            yield {"string": match.group().decode("ascii"), "offset": match.start()}

    def unicode_strings(self, buf, n=8):
        reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        uni_re = re.compile(reg)
        for match in uni_re.finditer(buf):
            try:
                yield {
                    "string": match.group().decode("utf-16"),
                    "offset": match.start(),
                }
            except UnicodeDecodeError:
                pass

    def strings(self, data, min_len=8):

        for s in self.ascii_strings(data, min_len):
            yield s

        if self.options.get("search_unicode"):
            for s in self.unicode_strings(data, min_len):
                yield s

    def process(self, sample):

        result = []
        ioc_blacklist = self.options.get("iocs_exclude")
        min_str_len = self.options.get("min_str_len")

        try:

            self.logger.debug("Extracting all strings (ASCII & Unicode)")
            # Extract all strings (ASCII & Unicode)
            strings_found = list(self.strings(sample["data"], min_str_len))

            self.logger.debug("Preprocessing strings")
            # Preprocess strings
            unique_strings = set(s["string"] for s in strings_found)

            for s in strings_found:
                result.append(s)

            self.logger.debug("Parsing strings for IOCs")
            # Parse strings for IOCs
            for s in unique_strings:

                self.logger.debug("Searching for IOCs")
                iocs = find_iocs(s, ioc_blacklist)

                for ioc_type, ioc_values in iocs.items():
                    if ioc_type == "ipv6s" and not self.options.get("extract_ipv6"):
                        continue
                    self.logger.debug(f"Adding IOC '{ioc_type}'")
                    self.add_ioc(ioc_type, ioc_values)

                if self.options.get("extract_resources"):
                    self.logger.debug("Extracting resources from IOCs")
                    self.extract_samples_from_iocs(iocs, sample["id"])

        except Exception as e:
            raise ProcessorRuntimeException(e)

        # Convert sets to lists because JSON can't handle sets
        return {"strings": result}

    def extract_samples_from_iocs(self, iocs, sample_id):

        extractable_iocs = {"domains": "domain", "ipv4s": "host", "urls": "url"}

        if self.options.get("extract_ipv6"):
            extractable_iocs["ipv6s"] = "host"

        if self.options.get("extract_email"):
            extractable_iocs["email_addresses"] = "meta/email"

        for ioc_type, ioc_values in iocs.items():

            if ioc_type in extractable_iocs.keys():

                meta_type = extractable_iocs[ioc_type]

                for sample_data in ioc_values:

                    # Skip domains extracted from URLs
                    if meta_type == "domain" and "urls" in iocs.keys():
                        if any(sample_data in url for url in iocs["urls"]):
                            continue

                    self.extract_meta_sample(meta_type, sample_data, sample_id)
