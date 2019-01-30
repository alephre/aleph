import pefile
import datetime

from aleph.common.base import ProcessorBase

class PEInfoProcessor(ProcessorBase):

    name = 'pe_info'
    mimetypes = ['application/x-dosexec']

    def process(self, sample):
        """Get Portable Executable (PE) files data

        Return example:

        {   'aslr': True,
            'dep': True,
            'seh': True,
            'architechture': '32-bit',
            'compilation_date': '2009-12-05 22:50:46',
            'compilation_timestamp': 1260053446,
            'number_sections': 5,
            'exports': [{'ordinal': 1, 'name': 'DriverProc', 'address': '0x1c202070'}, { ... } ],
            'imports': { 'LIB': [ { 'address': '0x407000', 'name': 'function'}, ... ], ... },
            'sections': [ { 'address': '0x1000', 'name': '.text','raw_size': 23552,'virtual_size': '0x5a5a'}, {  ... } ]
        }

        """

        tags = []

        try:
            pe = pefile.PE(data=sample['data'], fast_load=True)
            pe.parse_data_directories( directories=[ 
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

            data = {}

            # Get Architechture
            if pe.FILE_HEADER.Machine == 0x14C: # IMAGE_FILE_MACHINE_I386
                data['architechture'] = '32-bit'
                self.add_tag('i386')
            elif pe.FILE_HEADER.Machine == 0x8664: # IMAGE_FILE_MACHINE_AMD64
                data['architechture'] = '64-bit'
                self.add_tag('amd64')
            else:
                data['architechture'] = 'N/A'

            # Executable Type
            self.add_tag('dll' if pe.is_dll() else 'exe')
            if pe.is_driver():
                self.add_tag('driver')

            # Compilation time
            timestamp = pe.FILE_HEADER.TimeDateStamp

            if timestamp == 0:
                self.add_tag('no-timestamp')
            else:
                data['compilation_timestamp'] = timestamp
                data['compilation_date'] = datetime.datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                if (timestamp < 946692000): #@FIXME use constants or variables with meaningful names instead
                    self.add_tag('old-timestamp')
                elif (timestamp > datetime.datetime.utcnow().timestamp()):
                    self.add_tag('future-timestamp')

            data['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            data['image_base']  = pe.OPTIONAL_HEADER.ImageBase
            data['number_sections'] = pe.FILE_HEADER.NumberOfSections

            #check for ASLR, DEP/NX and SEH
            if pe.OPTIONAL_HEADER.DllCharacteristics > 0:
                if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                    data['aslr'] = True
                if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
                    data['dep'] = True
                if (pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400
                or (hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG") 
                and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount > 0 
                and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0) 
                or pe.FILE_HEADER.Machine == 0x8664):
                    data['seh'] = True

            # Check imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                imports = {}
                for lib in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = lib.dll.decode('utf-8')
                    imports[dll_name] = []

                    for imp in lib.imports:
                        if (imp.name != None) and (imp.name != ""):
                            imports[dll_name].append({'address': hex(imp.address), 'name': imp.name.decode('utf-8')})
                            
                data['imports'] = imports

            # Check exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                exports = []
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append({'address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), 'name': exp.name.decode('utf-8'), 'ordinal': exp.ordinal})
                    if exp.name == 'CPlApplet' and pe.is_dll():
                        self.add_tag('cpl')

                data['exports'] = exports

            # Get sections
            if len(pe.sections) > 0:
                data['sections'] = []
                for section in pe.sections:
                    data['sections'].append({'name': section.Name.decode('utf-8').strip('\u0000'), 'address': hex(section.VirtualAddress), 'virtual_size': hex(section.Misc_VirtualSize), 'raw_size': section.SizeOfRawData })
            
            return data
                            
        except Exception as e:
            raise 
