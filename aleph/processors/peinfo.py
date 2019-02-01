import pefile
import datetime

from itertools import zip_longest

from aleph.common.base import ProcessorBase
from aleph.common.utils import entropy, normalize_name

class PEInfoProcessor(ProcessorBase):

    name = 'pe_info'
    default_options = { 'enabled': True, 'extract_resources': False }
    mimetypes = ['application/x-dosexec']
    
    def extract_structure(self, data, force=[]):

        dictionary = {}

        for key in data.__keys__:
            keyname = key[0]
            attr = getattr(data, keyname)
            if isinstance(attr, (bytes, bytearray)):
                attr = attr.decode('utf-8')
            dictionary[normalize_name(keyname)] = attr

        if force:
            for key, default in force:
                if key not in dictionary.keys():
                    dictionary[normalize_name(key)] = default

        return dictionary


    def traverse_directory(self, node, path=[], timestamp = None):

        for entry in node.entries:

            new_path = path.copy()

            if hasattr(entry, 'directory'):
                if len(path) == 0:
                    timestamp = getattr(entry.directory, 'TimeDateStamp', None)
                new_path.append(entry.id)
                yield from self.traverse_directory(entry.directory, new_path.copy(), timestamp)
            elif hasattr(entry, 'data'):

                resource = {
                    'language': entry.id,
                    'name': entry.name.__str__() if entry.name else '',
                    'type': path[0],
                    'path': '/'.join([str(p) for p in path]),
                    'codepage': entry.data.struct.CodePage,
                    'offset': entry.data.struct.OffsetToData,
                    'size': entry.data.struct.Size,
                    'reserved': entry.data.struct.Reserved,
                    'timestamp': timestamp,
                }
                yield resource

    def process(self, sample):
        """Get Portable Executable (PE) files data"""

        try:
            pe = pefile.PE(data=sample['data'], fast_load=False)
            pe.parse_data_directories( directories=[ 
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'],
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

                data[h_name] = self.extract_structure(h_data)

            # Load Configuration
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                data['load_configuration'] = self.extract_structure(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, force=[('TimeDateStamp',None)])

            # Debug Information
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                debug_entries = []
                for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                    debug_entries.append(self.extract_structure(debug_entry.struct))

                data['debug_information'] = debug_entries

            # VS Version Information
            if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'FileInfo'):
                version_info = {}
                for entry in pe.FileInfo:
                    if hasattr(entry[0], 'StringTable'):
                        for st_entry in entry[0].StringTable:
                            for st_entry_name, st_entry_value in st_entry.entries.items():

                                st_entry_name = normalize_name(st_entry_name.decode('utf-8'))
                                st_entry_value = st_entry_value.decode('utf-8')

                                version_info[st_entry_name] = st_entry_value

                data['version_information'] = version_info

            # VS Fixed File Info
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                fixed_file_info = {}
                for finfo in pe.VS_FIXEDFILEINFO:
                    res = self.extract_structure(finfo)
                    for rk, rv in res.items():
                        fixed_file_info[rk] = rv.decode('utf-8') if isinstance(rv, (bytes, bytearray)) else rv

                data['fixed_file_info'] = fixed_file_info


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

            # Check for ASLR, DEP/NX and SEH mitigations
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
                data['imphash'] = pe.get_imphash()

                imports = {}
                for lib in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = lib.dll.decode('utf-8')
                    imports[dll_name] = []

                    for imp in lib.imports:
                        if (imp.name != None) and (imp.name != ""):
                            imports[dll_name].append({'address': hex(imp.address), 'name': imp.name.decode('utf-8')})
                            
                data['imports'] = imports
            
            # Check RICH header
            rich = pe.parse_rich_header()
            if rich:

                rich_values = dict(zip_longest(*[iter(rich['values'])] * 2, fillvalue=""))

                rich_header = {
                    'xor_key': rich['checksum'],
                    'compids': []
                }

                for compid, count in rich_values.items():

                    comp_type = (compid >> 16)
                    min_ver = (compid & 0xFFFF)

                    comp = {
                        'comp_id': compid,
                        'type_id': comp_type,
                        'min_ver': min_ver,
                        'count': count
                    }

                    rich_header['compids'].append(comp)

                data['rich_header'] = rich_header

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
