import lief

from aleph.models import Processor
from aleph.exceptions import ProcessorRuntimeException

class ELF(Processor):

    binary = None

    def process(self, sample):

        sample_data = sample['data']

        try:
            self.binary = lief.ELF.parse(raw=sample_data)
        except Exception as e:
            raise ProcessorRuntimeException("Unable to parse ELF file: %s" % str(e))

        metadata = {
            'entry_point': self.binary.entrypoint,
            'image_base': self.binary.imagebase,
            'virtual_size': self.binary.virtual_size,
            'header': self.get_header(),
            'sections': self.get_sections(),
            'segments': self.get_segments(),
            'static_symbols': self.get_symbols(),
            'dynamic_symbols': self.get_symbols(dynamic=True),
            'is_pie': self.binary.is_pie,
        }

        return metadata

    def get_header(self):

        header = self.binary.header

        return {
            'arm_flags_list': list(header.arm_flags_list),
            'file_type': str(header.file_type).split('.')[1],
            'size': header.header_size,
            'machine_type': str(header.machine_type).split('.')[1],
            'nr_sections': header.numberof_sections,
            'nr_segments': header.numberof_segments,
            'object_file_version': str(header.object_file_version).split('.')[1],
            'ppc64_flags_list': list(header.ppc64_flags_list),
            'processor_flag': header.processor_flag,
            'program_header_offset': header.program_header_offset,
            'program_header_size': header.program_header_size,
            'section_header_offset': header.section_header_offset,
            'section_header_size': header.section_header_size,
        }

    def get_sections(self):

        sections = []

        for section in self.binary.sections:

            section_data = {
                'name': section.name,
                'type': str(section.type).split('.')[1],
                'virtual_address': section.virtual_address,
                'size': section.size,
                'flags': section.flags,
                'entropy': section.entropy,
            }
            sections.append(section_data)

        return sections

    def get_segments(self):

        segments = []

        for segment in self.binary.segments:

            segment_data = {
                'type': str(segment.type).split('.')[1],
                'physical_address': segment.physical_address,
                'physical_size': segment.physical_size,
                'virtual_address': segment.virtual_address,
                'virtual_size': segment.virtual_size,
                'flags': str(segment.flags).split('.')[1],
            }
            segments.append(segment_data)

        return segments


    def get_symbols(self, dynamic=False):

        symbols = []

        symbol_iterator = self.binary.dynamic_symbols if dynamic else self.binary.static_symbols

        for symbol in symbol_iterator:
            
            symbol_data = {
                'name': symbol.name,
                'demangled_name': symbol.demangled_name,
                'type': str(symbol.type).split('.')[1],
                'size': symbol.size,
                'exported': symbol.exported,
                'imported': symbol.imported,
                'is_function': symbol.is_function,
                'is_variable': symbol.is_variable,
            }

            symbols.append(symbol_data)

        return symbols
