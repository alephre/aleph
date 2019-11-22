from operator import itemgetter
from time import sleep

from virus_total_apis import PrivateApi, PublicApi

from aleph.config.constants import FILETYPES_ARCHIVE
from aleph.helpers.datautils import hash_data
from aleph.helpers.strings import in_string
from aleph.models import Processor

VT_RESPONSE_OK = 200
VT_SCAN_OK = 1


class VirusTotal(Processor):

    name = "virustotal"
    category = "sandbox"

    default_options = {
        "report_sleep": 60,
        "retry_count": 10,
        "send_files": True,
        "enabled": False,
    }
    required_options = ["api_key"]

    filetypes_exclude = FILETYPES_ARCHIVE + ["text/url"]

    def setup(self):

        self.vt_key = self.options.get("api_key")
        self.vt_type = self.options.get("key_type", "")

        if self.vt_type == "public":
            self.vt = PublicApi(key=self.vt_key)

        elif self.vt_type == "":
            self.vt = PublicApi(key=self.vt_key)

        elif self.vt_type == "private":
            self.vt = PrivateApi(key=self.vt_key)

    def get(self, file_hash):

        result = self.vt.get_file_report(file_hash)

        if result["response_code"] is not VT_RESPONSE_OK:
            return None

        report = result["results"]

        if report["response_code"] is not VT_SCAN_OK:
            return None

        return report

    def scan(self, sample_data):

        retry_count = 0

        scan_request = self.vt.scan_file(sample_data, from_disk=False)
        file_hash = scan_request["results"]["sha256"]

        while retry_count <= self.options.get("retry_count"):

            sleep(self.options.get("report_sleep"))
            report = self.get(file_hash)

            if report:
                return report

            retry_count += 1

        raise RuntimeError("Maximum retries waiting for scan result for %s" % file_hash)

    def process(self, sample):

        file_hash = hash_data(sample["data"])

        report = self.get(file_hash)

        if not report:
            self.logger.info("Sample %s not found on VirusTotal" % file_hash)
            if not self.options.get("send_files"):
                return {"scan_id": "not found"}

            self.logger.info("Sending %s to VirusTotal" % file_hash)
            report = self.scan(sample["data"])

        detections = []

        for av, res in report["scans"].items():
            if res["detected"]:
                self.parse_av_tags(res["result"])
                detections.append(
                    {"av": av, "version": res["version"], "result": res["result"]}
                )

        if report["positives"] > 0:
            self.add_tag("malware")

        if self.key_type == "private":
            if len(report["tags"]) > 1:
                self.parse_tags(report["tags"])

            if len(report["ITW_urls"]):
                # add ITW urls as URL indicator
                for url in report["ITW_urls"]:
                    self.add_ioc("urls", url)

        return {
            "scan_id": report["scan_id"],
            "positives": report["positives"],
            "scan_date": report["scan_date"],
            "detections": sorted(detections, key=itemgetter("av")),
        }

    def parse_av_tags(self, malware_name):
        if in_string(["banker", "banload"], malware_name):
            self.add_tag("malware-banker")

        if in_string(["trojan"], malware_name):
            self.add_tag("malware-trojan")

        if in_string(["bot"], malware_name):
            self.add_tag("malware-botnet")

        if in_string(["rat"], malware_name):
            self.add_tag("malware-rat")

    def parse_tags_malware(self, tag):

        if tag in ["upx", "asprox", "themida"]:
            self.add_tag("malware-packed")

    def parse_tags_documents(self, tag):

        if tag == "macros":
            self.add_tag("document-contains-macros")

        if tag.startswith("auto-"):
            self.add_tag("document-contains-{0}".format(tag))

        if tag.endswith("-file"):
            self.add_tag("document-contains-{0}".format(tag))

        if tag == "powershell":
            self.add_tag("document-contains-powershell")

    def parse_tags_pdf(self, tag):

        if tag == "js-embedded":
            self.add_tag("pdf-contains-javascript")

        if tag == "flash-embedded":
            self.add_tag("pdf-contains-flash")

        if tag == "autoaction":
            self.add_tag("pdf-contains-autoaction")

        if tag == "acroform":
            self.add_tag("pdf-contains-acroform")

        if tag == "launch-action":
            self.add_tag("pdf-contains-launchaction")

        if tag == "file-embedded":
            self.add_tag("pdf-contains-embeddedfiles")

    def parse_tags_flash(self, tag):

        if tag == "obfuscated":
            self.add_tag("flash-obfuscated")

        if tag == "javascript":
            self.add_tag("flash-contains-javascript")

        ignore_tags = ["flash-embedded", "js-embedded", "file-embedded"]
        if tag.endswith("-embedded") and tag not in ignore_tags:
            # swap $type-embedded. i.e., converts to 'flash-contains-embedded-exe', etc.
            tag = tag.split("-")
            self.add_tag("flash-contains-{0}-".format(tag[1], tag[0]))

    def parse_tags(self, sample_tags):

        for tag in sample_tags:
            # malware packer specific
            self.parse_tags_malware(tag)

            # osx specific
            if tag == "dropper":
                self.add_tag("malware-dropper")

            # Tags to be captured as-is
            as_is_tags = ["encrypted", "exploit"]
            if tag in as_is_tags:
                self.add_tag(tag)

            # cves
            if "cve" in tag:
                self.add_tag(tag.lower())

            # document specific tags
            self.parse_tags_documents(tag)

            # pdf specific tags
            self.parse_tags_pdf(tag)

            # flash specific tags
            self.parse_tags_flash(tag)
