import datetime
from itertools import zip_longest

import pefile
from slugify import slugify

from aleph.helpers.datautils import entropy
from aleph.helpers.strings import normalize_name
from aleph.models import Processor


class PE(Processor):

    default_options = {"enabled": True, "extract_resources": True}
    filetypes = ["application/x-dosexec"]

    def extract_structure(self, data, force=[]):

        dictionary = {}

        for key in data.__keys__:
            keyname = key[0]
            attr = getattr(data, keyname)
            if isinstance(attr, (bytes, bytearray)):
                attr = attr.decode("utf-8")
            dictionary[normalize_name(keyname)] = attr

        if force:
            for key, default in force:
                if key not in dictionary.keys():
                    dictionary[normalize_name(key)] = default

        return dictionary

    def traverse_directory(self, node, path=[], timestamp=None):

        for entry in node.entries:

            new_path = path.copy()

            if hasattr(entry, "directory"):
                if len(path) == 0:
                    timestamp = getattr(entry.directory, "TimeDateStamp", None)
                new_path.append(entry.id)
                yield from self.traverse_directory(
                    entry.directory, new_path.copy(), timestamp
                )
            elif hasattr(entry, "data"):

                resource = {
                    "language": entry.id,
                    "name": entry.name.__str__() if entry.name else "",
                    "type": path[0],
                    "path": "/".join([str(p) for p in path]),
                    "codepage": entry.data.struct.CodePage,
                    "offset": entry.data.struct.OffsetToData,
                    "size": entry.data.struct.Size,
                    "reserved": entry.data.struct.Reserved,
                    "timestamp": timestamp,
                }
                yield resource

    def get_headers(self, pe):

        headers = {}
        header_sources = {
            "dos_header": pe.DOS_HEADER,
            "pe_header": pe.FILE_HEADER,
            "optional_header": pe.OPTIONAL_HEADER,
            "nt_headers": pe.NT_HEADERS,
        }

        for h_name, h_data in header_sources.items():

            headers[h_name] = self.extract_structure(h_data)

        return headers

    def get_load_config(self, pe):
        return self.extract_structure(
            pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, force=[("TimeDateStamp", None)]
        )

    def get_debug_info(self, pe):
        debug_entries = []
        for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
            debug_entries.append(self.extract_structure(debug_entry.struct))

        return debug_entries

    def get_version_info(self, pe):

        version_info = {}

        for entry in pe.FileInfo:
            if hasattr(entry[0], "StringTable"):
                for st_entry in entry[0].StringTable:
                    for (st_entry_name, st_entry_value) in st_entry.entries.items():

                        st_entry_name = normalize_name(st_entry_name.decode("utf-8"))
                        st_entry_value = st_entry_value.decode("utf-8")

                        version_info[st_entry_name] = st_entry_value

        return version_info

    def get_fixed_file_info(self, pe):
        fixed_file_info = {}
        for finfo in pe.VS_FIXEDFILEINFO:
            res = self.extract_structure(finfo)
            for rk, rv in res.items():
                fixed_file_info[rk] = (
                    rv.decode("utf-8") if isinstance(rv, (bytes, bytearray)) else rv
                )

        return fixed_file_info

    def get_imports(self, pe):

        imports = []

        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = lib.dll.decode("utf-8")
            import_timestamp = getattr(lib.struct, "TimeDateStamp", None)

            import_obj = {
                "name": dll_name,
                "timestamp": None if (import_timestamp == 0) else import_timestamp,
                "imports": [],
            }

            for imp in lib.imports:
                if imp.name:
                    import_obj["imports"].append(
                        {"address": hex(imp.address), "name": imp.name.decode("utf-8")}
                    )

            imports.append(import_obj)

        return imports

    def get_exports(self, pe):

        exports = []

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(
                {
                    "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                    "name": exp.name.decode("utf-8"),
                    "ordinal": exp.ordinal,
                }
            )
            if exp.name == "CPlApplet" and pe.is_dll():
                self.add_tag("cpl")

        return exports

    def get_sections(self, pe):

        sections = []

        for section in pe.sections:
            sections.append(
                {
                    "name": section.Name.decode("utf-8").strip("\u0000"),
                    "address": hex(section.VirtualAddress),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                    "entropy": section.get_entropy(),
                }
            )

        return sections

    def get_resources(self, pe, sample_id):

        resources = []

        for resource in self.traverse_directory(pe.DIRECTORY_ENTRY_RESOURCE):

            start, end = (resource["offset"], (resource["offset"] + resource["size"]))
            resource_data = pe.get_memory_mapped_image()[start:end]
            resource["entropy"] = entropy(resource_data)
            resources.append(resource)

            if self.options.get("extract_resources"):
                self.dispatch(
                    resource_data,
                    parent=sample_id,
                    filename="pe-resource-%s.res" % slugify(resource["path"]).lower(),
                )

        return resources

    def get_rich_header(self, rich):

        rich_values = dict(zip_longest(*[iter(rich["values"])] * 2, fillvalue=""))

        rich_header = {"xor_key": rich["checksum"], "compids": []}

        for compid, count in rich_values.items():

            comp_type = compid >> 16
            min_ver = compid & 0xFFFF

            comp = {
                "comp_id": compid,
                "type_id": comp_type,
                "min_ver": min_ver,
                "count": count,
            }

            rich_header["compids"].append(comp)

        return rich_header

    def get_mitigations(self, pe):

        mitigations = {"aslr": False, "dep": False, "seh": False}
        if pe.OPTIONAL_HEADER.DllCharacteristics > 0:
            if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                mitigations["aslr"] = True
            if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
                mitigations["dep"] = True
            if (
                pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400
                or (
                    hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG")
                    and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount > 0
                    and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0
                )
                or pe.FILE_HEADER.Machine == 0x8664
            ):
                mitigations["seh"] = True

        return mitigations

    def process(self, sample):
        """Get Portable Executable (PE) files data."""
        try:

            pe = pefile.PE(data=sample["data"], fast_load=False)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                ]
            )

            metadata = {}

            # Basic Headers
            metadata["headers"] = self.get_headers(pe)

            # Load Configuration
            if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
                metadata["load_configuration"] = self.get_load_config(pe)

            # Debug Information
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                metadata["debug_information"] = self.get_debug_info(pe)

            # VS Version Information
            if hasattr(pe, "VS_VERSIONINFO") and hasattr(pe, "FileInfo"):
                metadata["version_information"] = self.get_version_info(pe)

            # VS Fixed File Info
            if hasattr(pe, "VS_FIXEDFILEINFO"):
                metadata["fixed_file_info"] = self.get_fixed_file_info(pe)

            # Get Architechture
            if pe.FILE_HEADER.Machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
                self.add_tag("i386")
            elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                self.add_tag("amd64")

            # Executable Type
            self.add_tag("dll" if pe.is_dll() else "exe")
            if pe.is_driver():
                self.add_tag("driver")

            # Compilation time
            timestamp = pe.FILE_HEADER.TimeDateStamp

            if timestamp == 0:
                self.add_tag("no-timestamp")
            else:
                if (
                    timestamp < 946692000
                ):  # @FIXME use constants or variables with meaningful names instead
                    self.add_tag("old-timestamp")
                elif timestamp > datetime.datetime.utcnow().timestamp():
                    self.add_tag("future-timestamp")

            # Check for ASLR, DEP/NX and SEH mitigations
            metadata["mitigations"] = self.get_mitigations(pe)

            # Check imports & imphash
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                metadata["imphash"] = pe.get_imphash()
                metadata["imports"] = self.get_imports(pe)

            # Check RICH header
            rich = pe.parse_rich_header()
            if rich:
                metadata["rich_header"] = self.get_rich_header(rich)

            # Check exports
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                metadata["exports"] = self.get_exports(pe)

            # Get sections
            if len(pe.sections) > 0:
                metadata["sections"] = self.get_sections(pe)

            # Get resources
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                metadata["resources"] = self.get_resources(pe, sample["id"])

            return metadata

        except Exception:
            raise
