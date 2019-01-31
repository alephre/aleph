import pefile
import datetime

from aleph.common.base import ProcessorBase
from aleph.common.utils import entropy, normalize_name

RESOURCE_TYPES = {
    1: 'RT_CURSOR',
    2: 'RT_BITMAP',
    3: 'RT_ICON',
    4: 'RT_MENU',
    5: 'RT_DIALOG',
    6: 'RT_STRING',
    7: 'RT_FONTDIR',
    8: 'RT_FONT',
    9: 'RT_ACCELERATOR', 
    10: 'RT_RCDATA',
    11: 'RT_MESSAGETABLE',
    12: 'RT_GROUP_CURSOR',
    14: 'RT_GROUP_ICON',
    16: 'RT_VERSION',
    17: 'RT_DLGINCLUDE',
    19: 'RT_PLUGPLAY',
    20: 'RT_VXD',
    21: 'RT_ANICURSOR', 
    22: 'RT_ANIICON',
    23: 'RT_HTML',
    24: 'RT_MANIFEST',
}

class PEInfoProcessor(ProcessorBase):

    name = 'pe_info'
    default_options = { 'enabled': True, 'extract_resources': False }
    mimetypes = ['application/x-dosexec']
    
    def traverse_directory(self, node, path=[]):
        
        for entry in node.entries:

            new_path = path.copy()

            if hasattr(entry, 'directory'):
                _path = RESOURCE_TYPES.get(entry.id, entry.id) if not path else entry.id
                new_path.append(_path)
                yield from self.traverse_directory(entry.directory, new_path.copy())
            elif hasattr(entry, 'data'):

                resource = {
                    'id': entry.id,
                    'name': entry.name.__str__() if entry.name else '',
                    'type': path[0],
                    'path': '/'.join([str(p) for p in path]),
                    'codepage': entry.data.struct.CodePage,
                    'language': '@IMPLEMENTME',
                    'offset': entry.data.struct.OffsetToData,
                    'size': entry.data.struct.Size,
                    'reserved': entry.data.struct.Reserved,
                    'timestamp': '@IMPLEMENTME',
                }
                yield resource

    def process(self, sample):
        """Get Portable Executable (PE) files data"""

        try:
            pe = pefile.PE(data=sample['data'], fast_load=True)
            pe.parse_data_directories( directories=[ 
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

            data = {}

            # Basic Headers
            headers = {
                'dos_header': pe.DOS_HEADER,
                'pe_header': pe.FILE_HEADER,
                'optional_header': pe.OPTIONAL_HEADER,
                'nt_headers': pe.NT_HEADERS,
            }
            for h_name, h_data in headers.items():
                header_data = {}
                for key in h_data.__keys__:
                    keyname = key[0]
                    attr = getattr(h_data, keyname)
                    if isinstance(attr, (bytes, bytearray)):
                        attr = attr.decode('utf-8')
                    elif isinstance(attr, int):
                        attr = hex(attr)
                    header_data[normalize_name(keyname)] = attr

                data[h_name] = header_data

            # Get Architechture
            if pe.FILE_HEADER.Machine == 0x14C: # IMAGE_FILE_MACHINE_I386
                self.add_tag('i386')
            elif pe.FILE_HEADER.Machine == 0x8664: # IMAGE_FILE_MACHINE_AMD64
                self.add_tag('amd64')

            # Executable Type
            self.add_tag('dll' if pe.is_dll() else 'exe')
            if pe.is_driver():
                self.add_tag('driver')

            # Compilation time
            timestamp = pe.FILE_HEADER.TimeDateStamp

            if timestamp == 0:
                self.add_tag('no-timestamp')
            else:
                if (timestamp < 946692000): #@FIXME use constants or variables with meaningful names instead
                    self.add_tag('old-timestamp')
                elif (timestamp > datetime.datetime.utcnow().timestamp()):
                    self.add_tag('future-timestamp')

            #check for ASLR, DEP/NX and SEH mitigations
            data['mitigations'] = {}
            if pe.OPTIONAL_HEADER.DllCharacteristics > 0:
                if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                    data['mitigations']['aslr'] = True
                if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
                    data['mitigations']['dep'] = True
                if (pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400
                or (hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG") 
                and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount > 0 
                and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0) 
                or pe.FILE_HEADER.Machine == 0x8664):
                    data['mitigations']['seh'] = True

            # Check imports & imphash
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                #@IMPLEMENTME imphash
                imports = {}
                for lib in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = lib.dll.decode('utf-8')
                    imports[dll_name] = []

                    for imp in lib.imports:
                        if (imp.name != None) and (imp.name != ""):
                            imports[dll_name].append({'address': hex(imp.address), 'name': imp.name.decode('utf-8')})
                            
                data['imports'] = imports
            
            # Check RICH header
            # @IMPLEMENTME

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
                    data['sections'].append(
                        {
                            'name': section.Name.decode('utf-8').strip('\u0000'), 
                            'address': hex(section.VirtualAddress), 
                            'virtual_size': hex(section.Misc_VirtualSize), 
                            'raw_size': section.SizeOfRawData,
                            'characteristics': hex(section.Characteristics),
                            'entropy': section.get_entropy(),
                        })

            # Get resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                data['resources'] = []
                for resource in self.traverse_directory(pe.DIRECTORY_ENTRY_RESOURCE):

                    resource_data = pe.get_memory_mapped_image()[resource['offset']:resource['offset']+resource['size']]
                    resource['entropy'] = entropy(resource_data)
                    data['resources'].append(resource)

                    if self.options.get('extract_resources'):
                        self.dispatch(resource_data, parent=sample['id'], filename=resource['path'])

            return data
                            
        except Exception as e:
            raise 
