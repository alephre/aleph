import re

from io import BytesIO
from decimal import Decimal

from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument

from aleph.models import Processor
from aleph.exceptions import ProcessorRuntimeException
from aleph.helpers.strings import normalize_name

from aleph.helpers.pdfid.pdfid import PDFiD
from aleph.helpers.pdfid.pdfid import PDFiD2JSON


class PDF(Processor):

    filetypes = ["application/pdf"]

    def process(self, sample):
        """Get PDF document metadata and encryption information.

        @param sample: raw data of sample to process
        @type unicode

        @return results: dictionary containg PDF metadata and suspicious content
        @rtype dict
        """
        results = {}

        # get basic metadata information on PDF
        with BytesIO(sample["data"]) as pdf_io:
            parser = PDFParser(pdf_io)
            document = PDFDocument(parser)

        parser.set_document(document)

        if document.encryption is not None:
            results["encryption"] = {
                "id": document.encryption[0],
                "encrypt": document.encryption[1],
            }
            self.add_tag("encrypted")

        if len(document.info) > 0:
            doc_info = document.info[0]
            for k, v in doc_info.items():
                results[normalize_name(k)] = v.decode("utf-8", errors="ignore")
        else:
            self.logger.debug(
                "No metadata available from PDF document (%s)" % sample["id"]
            )
            self.add_tag("no-metadata")

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
                    file=BytesIO(sample["data"]),
                    allNames=True,
                    extraData=True,
                    disarm=False,
                    force=True,
                ),
                force=True,
            )

        except Exception:
            self.logger.warn(
                "caught exception with 'extraData' argument; disabling and continuing"
            )
            pdfid_out = PDFiD2JSON(
                PDFiD(
                    file=BytesIO(sample["data"]),
                    allNames=True,
                    extraData=False,
                    disarm=False,
                    force=True,
                ),
                force=True,
            )
            extra_data = False

        if not isinstance(pdfid_out, dict):
            self.logger.error("failed to parse pdfid output to JSON")
            raise ProcessorRuntimeException("failed to parse pdfid output to JSON")

        return (pdfid_out, extra_data)

    def parse_pdfid(self, jdata, extra=None):

        results = {}

        # get basic data
        results["filename"] = jdata["filename"]

        if not re.match(r"%PDF-1\.\d", jdata["version"]):
            results["header"] = "Invalid PDF version: %s" % jdata["Header"]

        if "totalEntropy" in jdata.keys():
            results["total_entropy"] = jdata["TotalEntropy"]

        if "streamEntropy" in jdata.keys():
            results["stream_entropy"] = jdata["streamEntropy"]

        if "nonStreamEntropy" in jdata.keys():
            results["nonstream_entropy"] = jdata["nonStreamEntropy"]

        if extra:
            self.get_pdf_entropy(
                results["total_entropy"],
                results["stream_entropy"],
                results["nonstream_entropy"],
            )

        tags_dict = {
            "/JS": 0,
            "/AcroForm": 0,
            "/AA": 0,
            "/AutoAction": 0,
            "/OpenAction": 0,
            "/LaunchAction": 0,
            "/EmbeddedFiles": 0,
            "/URI": 0,
            "/Pages": 0,
            "/Page": 0,
        }

        for keyword in jdata["keywords"]["keyword"]:
            kw_name, kw_count = keyword["name"], keyword["count"]
            tags_dict[kw_name] = kw_count

        tags = {
            "javascript": tags_dict["/JS"],
            "acroform": tags_dict["/AcroForm"],
            "additional_action": tags_dict["/AA"],
            "auto_action": tags_dict["/AutoAction"],
            "open_action": tags_dict["/OpenAction"],
            "launch_action": tags_dict["/LaunchAction"],
            "embedded_files": tags_dict["/EmbeddedFiles"],
            "uri": tags_dict["/URI"],
            "pages": tags_dict["/Pages"],
            "page": tags_dict["/Page"],
        }

        results["pages"] = tags["pages"] if tags["pages"] else tags["page"]

        # @FIXME use add_flag directly
        if results["pages"] == 2:
            self.add_tag("pdf-suspicious")
        elif results["pages"] == 1:
            self.add_tag("pdf-single-page")
            self.add_tag("pdf-suspicious")

        return results

    def get_pdf_entropy(self, total, stream, nonstream):

        te_long = Decimal(total)
        te_short = Decimal(total[0:3])

        # ie_long = Decimal(stream) # @FIXME unused
        ie_short = Decimal(stream[0:3])

        oe_long = Decimal(nonstream)
        # oe_short = Decimal(nonstream[0:3]) # @FIXME unused
        # ent = (te_short + ie_short) / 2 # @FIXME unused

        # Don't want to apply this if it goes over the max of 8
        togo = 8 - oe_long

        if togo > 2:
            if oe_long + 2 > te_long:
                self.add_tag("questionable_entropy")

        elif oe_long > te_long:
            self.add_tag("questionable_entropy")

        if str(te_short) <= "2.0" or str(ie_short) <= "2.0":
            self.add_tag("low_entropy")
