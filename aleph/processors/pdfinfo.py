from io import BytesIO

from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument

from aleph.models import Processor
from aleph.helpers.strings import normalize_name

from aleph.helpers.pdfid.pdfid import PDFiD
from aleph.helpers.pdfid.pdfid import PDFiD2JSON


class PDFInfo(Processor):

    name = 'pdf_info'
    filetypes = ['application/pdf']

    def process(self, sample):
        """Get PDF document metadata and encryption information

        @param sample: raw data of sample to process
        @type unicode

        @return results: dictionary containg PDF metadata and suspicious content
        @rtype dict
        """

        results = {}

        # get basic metadata information on PDF
        with BytesIO(sample['data']) as pdf_io:
            parser = PDFParser(pdf_io)
            document = PDFDocument(parser)

        parser.set_document(document)

        if document.encryption is not None:
            results['encryption'] = {
                'ID': document.encryption[0],
                'Encrypt': document.encryption[1]
            }
            self.add_tag('encrypted')

        if len(document.info) > 0:
            doc_info = document.info[0]
            for k, v in doc_info.items():
                results[normalize_name(k)] = v.decode('utf-8', errors='ignore')
        else:
            self.logger.debug('No metadata available from PDF document (%s)' % sample['id'])
            self.add_tag('no-metadata')

        # handle PDFiD execution and parsing
        pdfid_output, extra_data = self.run_pdfid(sample)
        results.update(self.parse_pdfid(pdfid_output, extra=extra_data))

        return results

    def run_pdfid(self, sample):

        extra_data = True

        try:
            # args = ((file, all names, extra data, disarm, force), force)
            pdfid_out = PDFiD2JSON(
                PDFiD(
                    file=BytesIO(sample['data']), allNames=True, extraData=True,
                    disarm=False, force=True
                ), force=True
            )

        except Exception as err:
            self.logger.warn('caught exception with 'extraData' argument; disabling and continuing')
            pdfid_out = PDFiD2JSON(
                PDFiD(
                    file=BytesIO(sample['data']), allNames=True, extraData=False,
                    disarm=False, force=True
                ), force=True
            )
            extra_data = False

        if not isinstance(pdfid_out, dict):
            self.logger.error('failed to parse pdfid output to JSON')
            raise ProcessorException('failed to parse pdfid output to JSON')

        return (pdfid_out, extra_data)

    def parse_pdfid(self, jdata):

        # get basic data
        results['Filename'] = jdata['filename']

        if not re.match('%PDF-1\.\d', jdata['version']):
            results['Header'] = 'Invalid PDF version: {0}'.format(jdata['Header'])

        if 'totalEntropy' in jdata.keys():
            results['total_entropy'] = jdata['TotalEntropy']

        if 'streamEntropy' in jdata.keys():
            results['stream_entropy'] = jdata['streamEntropy']

        if 'nonStreamEntropy' in jdata.keys():
            results['nonstream_entropy'] = jdata['nonStreamEntropy']

        if extra_data:
            self.get_pdf_entropy(results['total_entropy'], results['stream_entropy'], results['nonstream_entropy'])

        for keyword in jdata['keywords']['keyword']:
            # get page count and add tags if document contains small
            # number of pages. single page PDF are often malicious,
            # 3 pages or less is just as suspicious
            if keyword['name'] == '/Pages':
                results['Pages'] = keyword['count']
            if keyword['name'] == '/Page':
                results['Pages'] = keyword['count']

            if len(results['Pages']) <= 2:
                self.add_tag('pdf-suspicious')
            elif len(results['Pages']) == 1:
                self.add_tag('pdf-single-page')
                self.add_tag('pdf-suspicious')

            if keyword['count']:
                if keyword['name'] == '/JS':
                    results['javascript'] = 'Contains {0} /JS tag'.format(keyword['count'])
                    self.add_tag('pdf-contains-javascript')

                if keyword['name'] == '/AcroForm':
                    results['javascript'] = 'Contains {0} /JS tag'.format(keyword['count'])
                    self.add_tag('pdf-contains-javascript')

                if keyword['name'] == '/AA':
                    results['additional_action'] = 'Contains {0} /AA tag'.format(keyword['count'])
                    self.add_tag('pdf-contains-aa')

                if keyword['name'] == '/AutoAction':
                    results['auto_action'] = 'Contains {0} /AutoAction tags'.format(keyword['count'])
                    self.add_tag('pdf-contains-autoaction')

                if keyword['name'] == '/OpenAction':
                    results['open_action'] = 'Contains {0} /OpenAction tags'.format(keyword['count'])
                    self.add_tag('pdf-contains-openaction')

                if keyword['name'] == '/LaunchAction':
                    results['launch_ction'] = 'Contains {0} /Launch actions'.format(keyword['count'])
                    self.add_tag('pdf-contains-launchaction')

                if keyword['name'] == '/EmbeddedFiles':
                    results['Embedded Files'] = 'Contains {0} /EmbeddedFiles tags'.format(keyword['count'])
                    self.add_tag('pdf-contains-embeddedfiles')

                if keyword['uri'] == '/URI':
                    results['Additional Action'] = 'Contains {0} URI tags'.format(keyword['count'])
                    self.add_tag('pdf-contains-uri')

        return results

    def get_pdf_entropy(total, stream, nonstream):

        te_long = Decimal(results['total_entropy'])
        te_short = Decimal(results['total_entropy'][0:3])

        ie_long = Decimal(results['stream_entropy'])
        ie_short = Decimal(results['stream_entropy'][0:3])

        oe_long = Decimal(results['nonstream_entropy'])
        oe_short = Decimal(results['nonstream_entropy'][0:3])
        ent = (te_short + ie_short) / 2

        togo = (8 - oe_long)  # Don't want to apply this if it goes over the max of 8

        if togo > 2:
            if oe_long + 2 > te_long:
                self.add_tag('questionable_entropy')

        elif oe_long > te_long:
            self.add_tag('questionable_entropy')

        if str(te_short) <= '2.0' or str(ie_short) <= '2.0':
            self.add_tag('low_entropy')
