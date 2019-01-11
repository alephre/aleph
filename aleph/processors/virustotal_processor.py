from time import sleep
from operator import itemgetter

from virus_total_apis import PublicApi as VirusTotal

from aleph.utils import hash_data, in_string
from aleph.base import ProcessorBase
from aleph.constants import MIMETYPES_ARCHIVE

VT_RESPONSE_OK = 200
VT_SCAN_OK = 1

class VirusTotalProcessor(ProcessorBase):

    name = 'virustotal'
    category = 'sandbox'

    default_options = {'report_sleep': 60, 'retry_count': 10, 'send_files': True, 'enabled': False}
    required_options = ['api_key']
    mimetypes_except = MIMETYPES_ARCHIVE + ['text/url']

    def setup(self):

        self.vt = VirusTotal(self.options.get('api_key'))

    def get(self, file_hash):

        result = self.vt.get_file_report(file_hash)

        if result['response_code'] is not VT_RESPONSE_OK:
            return None

        report = result['results']

        if report['response_code'] is not VT_SCAN_OK:
            return None

        return report

    def scan(self, sample_data):

        retry_count = 0

        scan_request = self.vt.scan_file(sample_data, from_disk=False)
        file_hash = scan_request['results']['sha256']

        while (retry_count <= self.options.get('retry_count')):

            sleep(self.options.get('report_sleep'))
            report = self.get(file_hash)

            if report:
                return report

            retry_count += 1

        raise RuntimeError("Maximum retries waiting for scan result for %s" % file_hash)

    def process(self, sample):

        file_hash = hash_data(sample['data'])

        report = self.get(file_hash)

        if not report:
            self.logger.info('Sample %s not found on VirusTotal' % file_hash)
            if not self.options.get('send_files'):
                return {'scan_id': 'not found'}

            self.logger.info('Sending %s to VirusTotal' % file_hash)
            report = self.scan(sample['data'])

        detections = []

        for av, res in report['scans'].items():
            if res['detected']:
                self.parse_tags(res['result'])
                detections.append({
                    'av': av,
                    'version': res['version'],
                    'result': res['result'],
                })

        if report['positives'] > 0:
            self.add_tag('malware')

        return {
            'scan_id': report['scan_id'],
            'positives': report['positives'],
            'scan_date': report['scan_date'],
            'detections': sorted(detections, key=itemgetter('av')),
        }

    def parse_tags(self, malware_name):
        if in_string(['banker', 'banload'], malware_name):
            self.add_tag('malware-banker')

        if in_string(['trojan'], malware_name):
            self.add_tag('malware-trojan')

        if in_string(['bot'], malware_name):
            self.add_tag('malware-botnet')

        if in_string(['rat'], malware_name):
            self.add_tag('malware-rat')
