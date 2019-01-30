#!/usr/bin/env python3
from io import BytesIO

from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument

from aleph.common.base import ProcessorBase


class PDFInfoProcessor(ProcessorBase):

    name = 'pdf_info'
    mimetypes = ['application/pdf']

    def process(self, sample):
        """Get PDF document metadata and encryption information

        @param sample: raw data of sample to process
        @type unicode

        @return results: dictionary containg PDF metadata
        @rtype dict

        Return example:
            {
                'CreationDate': b"D:20170214195029-05'00'",
                'Creator': b'Adobe InDesign CC 2017 (Macintosh)',
                'ModDate': b"D:20170510110714-04'00'",
                'Producer': b'Adobe PDF Library 15.0',
                'Trapped': /'False'
            }
        """
        results = {}

        try:
            pdf_io = BytesIO(sample['data'])
            pdf_io.close()
        except Exception as err:
            self.logger.error(f'Failed to read PDF document into parser: {sample['id']} - {str(err)}')
            raise err

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
            results.update(doc_info)
        else:
            self.logger.info(f'No metadata available from PDF document: {sample['id']}')
            self.add_tag('no-metadata')

        return results
