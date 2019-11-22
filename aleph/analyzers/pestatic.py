import re

from aleph.helpers.mitre_attack import (
    MA_ACCESS_TOKEN_MANIP,
    MA_AUDIO_CAPTURE,
    MA_DATA_COMPRESSED,
    MA_DATA_ENCRYPTED,
    MA_EXECUTION_API,
    MA_EXFIL_NETWORK,
    MA_EXTRA_WINDOW_MEMORY_INJECTION,
    MA_FILE_PERMISSIONS_MODIFY,
    MA_HOOKING,
    MA_INDICATOR_REMOVAL_HOST,
    MA_MODIFY_EXISTING_SERVICE,
    MA_NEW_SERVICE,
    MA_PROCESS_DISCOVERY,
    MA_PROCESS_DOPPELGANGING,
    MA_PROCESS_HOLLOWING,
    MA_PROCESS_INJECTION,
    MA_REG_QUERY,
    MA_SCREEN_CAPTURE,
    MA_SECURITY_SOFTWARE_DISCOVERY,
    MA_SOFTWARE_PACKING,
    MA_SYSTEM_INFO_DISCOVERY,
    MA_SYSTEM_SERVICE_DISCOVERY,
)
from aleph.models import Analyzer

IMPORT_MIN_MATCHES = 2
EVIL_RES_SIZE_RATIO = 0.75
EVIL_ENTROPY_THRESHOLD = 7

RICH_COMPTYPE_TOTAL_IMPORTS = 0x001


class PEStatic(Analyzer):

    filetypes = ["application/x-dosexec"]

    # Mostly taken from <https://github.com/JusticeRage/Manalyze/blob/master/plugins/plugin_imports.cpp>
    evil_imports = {
        "anti_debug": {
            "description": "Imports functions commonly used to detect/evade/deter debugging",
            "severity": "uncommon",
            "rules": [
                "FindWindow(A|W)",
                "(Zw|Nt)QuerySystemInformation",
                "DbgBreakPoint",
                "DbgPrint",
                "CheckRemoteDebuggerPresent",
                "CreateToolhelp32Snapshot",
                "Toolhelp32ReadProcessMemory",
                "OutputDebugString",
                "SwitchToThread",
                "NtQueryInformationProcess",
            ],
            "mitre_attack_id": [MA_SECURITY_SOFTWARE_DISCOVERY],
        },
        "vanilla_injection": {
            "description": "Imports functions commonly used on vanilla code injection techniques",
            "severity": "uncommon",
            "rules": [
                "(Nt)?VirtualAlloc.*",
                "(Nt)?WriteProcessMemory",
                "CreateRemoteThread(Ex)?",
                "(Nt)?OpenProcess",
            ],
            "mitre_attack_id": [MA_PROCESS_INJECTION],
        },
        "process_hollowing": {
            "description": "Imports functions commonly used on process hollowiing code injection techniques",
            "severity": "uncommon",
            "rules": [
                "(Nt)?WriteProcessMemory",
                "(Nt)?WriteVirtualMemory",
                "(Wow64)?SetThreadContext",
                "(Nt)?ResumeThread",
                "(Nt)?SetContextThread",
            ],
            "mitre_attack_id": [MA_PROCESS_HOLLOWING],
        },
        "power_loader": {
            "description": "Imports functions commonly used on power loader code injection techniques",
            "severity": "uncommon",
            "rules": ["FindWindow(A|W)", "GetWindowLong(A|W)"],
            "mitre_attack_id": [MA_EXTRA_WINDOW_MEMORY_INJECTION],
        },
        "atom_bombing": {
            "description": "Imports functions commonly used on atom bombing code injection techniques",
            "severity": "uncommon",
            "rules": ["GlobalAddAtom(A|W)", "GlobalGetAtomName(A|W)" "QueueUserAPC"],
            "mitre_attack_id": [MA_PROCESS_INJECTION],
        },
        "process_doppelganging": {
            "description": "Imports functions commonly used on process doppelganging code injection techniques",
            "severity": "uncommon",
            "rules": [
                "CreateTransaction",
                "CreateFileTransacted",
                "RollbackTransaction",
                "(Nt)?WriteFile",
            ],
            "mitre_attack_id": [MA_PROCESS_DOPPELGANGING],
        },
        "keylogger_api": {
            "description": "Imports functions commonly used by keyloggers",
            "severity": "suspicious",
            "min_match": 1,
            "rules": [
                "SetWindowsHook(Ex)?",
                "GetAsyncKeyState",
                "GetForegroundWindow",
                "AttachThreadInput",
                "CallNextHook(Ex)?",
                "MapVirtualKey(A|W|Ex)",
            ],
            "mitre_attack_id": [MA_HOOKING],
        },
        "raw_socket_api": {
            "description": "Imports functions to handle raw sockets",
            "severity": "uncommon",
            "rules": [
                "accept",
                "bind",
                "connect",
                "recv",
                "send",
                "gethost(by)?name",
                "inet_addr",
            ],
            "mitre_attack_id": [MA_EXFIL_NETWORK],
        },
        "http_api": {
            "description": "Imports functions for HTTP communication",
            "severity": "info",
            "min_match": 1,
            "rules": ["Internet.*", "URL(Download|Open).*", "WinHttp.*"],
            "mitre_attack_id": [MA_EXFIL_NETWORK],
        },
        "crypto_api": {
            "description": "Imports functions from the Windows Cryptographic API",
            "severity": "uncommon",
            "min_match": 1,
            "rules": [
                "Crypt(Acquire|Release)Context(A|W)?",
                "Crypt.*(Key|Hash).*",
                "(B|N)Crypt.*",
                "Ssl.*",
            ],
            "mitre_attack_id": [MA_DATA_ENCRYPTED],
        },
        # @FIXME Separate into query/modify so we can have different ATT&CK IDs
        "registry_api": {
            "description": "Imports functions that alter the Windows Registry",
            "severity": "info",
            "min_match": 1,
            "rules": [
                "Reg.*(Key|Value).*",
                "SH.*(Reg|Key).*",
                "SHQueryValueEx(A|W)",
                "SHGetValue(A|W)",
            ],
            "mitre_attack_id": [MA_REG_QUERY],
        },
        "process_creation_api": {
            "description": "Imports functions commonly used to create processes",
            "severity": "info",
            "min_match": 1,
            "rules": ["(Nt)?CreateProcess.*", "system", "WinExec", "ShellExecute(A|W)"],
            "mitre_attack_id": [MA_EXECUTION_API],
        },
        "process_enumeration_api": {
            "description": "Imports functions commonly used for enumerating processes",
            "severity": "suspicious",
            "min_match": 1,
            "rules": ["EnumProcess.*", "Process32(First|Next)(A|W)?"],
            "mitre_attack_id": [MA_PROCESS_DISCOVERY],
        },
        "service_discovery_api": {
            "description": "Imports functions commonly used on Windows Services discovery",
            "severity": "uncommon",
            "rules": [
                "OpenSCManager(A|W)",
                "QueryService.*",
                "EnumServicesStatus(Ex)?(A|W)",
            ],
            "mitre_attack_id": [MA_SYSTEM_SERVICE_DISCOVERY],
        },
        "service_manipulation_api": {
            "description": "Imports functions commonly used on Windows Services manipulation",
            "severity": "uncommon",
            "rules": ["(Open|Control|Delete)Service(A|W)?", "ChangeServiceConfig(A|W)"],
            "mitre_attack_id": [MA_MODIFY_EXISTING_SERVICE],
        },
        "service_creation_api": {
            "description": "Imports functions commonly used on Windows Services creation",
            "severity": "uncommon",
            "rules": ["CreateService(A|W)?"],
            "mitre_attack_id": [MA_NEW_SERVICE],
        },
        "privilege_api": {
            "description": "Imports functions commonly used on privilege escalation",
            "severity": "suspicious",
            "rules": [
                "AdjustTokenPrivileges",
                "IsNTAdmin",
                "LsaEnumerateLogonSessions",
                "SamQueryInformationUser",
                "SamIGetPrivateData",
                "SfcTerminateWatcherThread",
                "(Zw)?OpenProcessToken(Ex)?",
                "(Zw)?DuplicateToken(Ex)?",
                "(SHTest|Check)TokenMembership",
            ],
            "mitre_attack_id": [MA_ACCESS_TOKEN_MANIP],
        },
        "dacl_api": {
            "description": "Imports DACL functions, used to change security attributes from objects",
            "severity": "info",
            "rules": [
                "SetKernelObjectSecurity"
                "SetFileSecurity(A|W)"
                "SetNamedSecurityInfo(A|W)"
                "SetSecurityInfo"
            ],
            "mitre_attack_id": [MA_FILE_PERMISSIONS_MODIFY],
        },
        "dynamic_import": {
            "description": "Imports functions that load libraries dynamically",
            "severity": "info",
            "min_match": 1,
            "rules": [
                "(Co)?LoadLibrary(Ex)?(A|W)",
                "GetProcAddress",
                "LdrLoadDll",
                "MmGetSystemRoutineAddress",
            ],
            "mitre_attack_id": [],
        },
        "temporary_files": {
            "description": "Imports functions to create temporary files",
            "severity": "info",
            "rules": ["GetTempPath(A|W)", "(Create|Write)File(A|W)"],
            "mitre_attack_id": [],
        },
        "hdd_enumeration": {
            "description": "Imports functions commonly used to enumerate disk drives",
            "severity": "info",
            "min_match": 1,
            "rules": [
                "GetVolumeInformation(ByHandle)?(A|W)",
                "GetDriveType(A|W)",
                "GetLogicalDriveStrings(A|W)",
            ],
            "mitre_attack_id": [MA_SYSTEM_INFO_DISCOVERY],
        },
        "driver_enumeration": {
            "description": "Imports functions commonly used to enumerate drivers",
            "severity": "info",
            "min_match": 1,
            "rules": ["EnumDeviceDrivers", "GetDeviceDriver.*"],
            "mitre_attack_id": [MA_SYSTEM_INFO_DISCOVERY],
        },
        "eventlog_deletion": {
            "description": "Imports functions used to delete Windows Event Logs",
            "severity": "suspicious",
            "min_match": 1,
            "rules": ["EvtClearLog", "ClearEventLog(A|W)"],
            "mitre_attack_id": [MA_INDICATOR_REMOVAL_HOST],
        },
        "screenshot_api": {
            "description": "Imports functions commonly used to capture the device screen",
            "severity": "uncommon",
            "rules": [
                "CreateCompatibleDC",
                "GetDC(Ex)?",
                "FindWindow(A|W)",
                "PrintWindow",
                "BitBlt",
            ],
            "mitre_attack_id": [MA_SCREEN_CAPTURE],
        },
        "audio_api": {
            "description": "Imports functions from the Audio API that could be used to intercept conversations",
            "severity": "uncommon",
            "min_match": 1,
            "rules": ["waveInOpen", "DirectSoundCaptureCreate.*"],
            "mitre_attack_id": [MA_AUDIO_CAPTURE],
        },
        "shutdown_functions": {
            "description": "Imports functions used to shutdown the OS",
            "severity": "info",
            "min_match": 1,
            "rules": [
                "Initiate(System)?Shutdown(Ex)?(A|W)",
                "LockWorkStation",
                "ExitWindows(Ex)?",
            ],
            "mitre_attack_id": [],
        },
        "networking_api": {
            "description": "Imports functions that configures networking",
            "severity": "info",
            "min_match": 1,
            "rules": [
                "(Un)?EnableRouter",
                "SetAdapterIpAddress",
                "SetIp(Forward|Net|Statistics|TTL).*",
                "SetPerTcp(6)?ConnectionEStats",
            ],
            "mitre_attack_id": [],
        },
    }

    known_packer_sections = [
        {
            "rule": r"\.ndata",
            "description": "The PE is an NSIS installer",
            "severity": "info",
        },
        {
            "rule": r"\.?(upx|UPX)[0-9!]",
            "description": "The PE is packed with UPX",
            "severity": "uncommon",
        },
        {
            "rule": r"\.(mpress|MPRESS)[0-9]",
            "description": "The PE is packed with mpress",
            "severity": "uncommon",
        },
        {
            "rule": r"\.[Aa][Ss][Pp]ack",
            "description": "The PE is packed with Aspack",
            "severity": "uncommon",
        },
        {
            "rule": r"\.ccg",
            "description": "The PE is packed with CCG",
            "severity": "uncommon",
        },
        {
            "rule": r"\.charmve|\.pinclie",
            "description": "The program is instrumented with PIN",
            "severity": "uncommon",
        },
        {
            "rule": r"BitArts",
            "description": "The PE is packed with Crunch 2.0",
            "severity": "uncommon",
        },
        {
            "rule": r"DAStub",
            "description": "The PE is packed with Dragon Armor",
            "severity": "uncommon",
        },
        {
            "rule": r"!EPack",
            "description": "The PE is packed with Epack",
            "severity": "uncommon",
        },
        {
            "rule": r"\.gentee",
            "description": "The PE is a gentee installer",
            "severity": "uncommon",
        },
        {
            "rule": r"kkrunchy",
            "description": "The PE is packed with kkrunchy",
            "severity": "uncommon",
        },
        {
            "rule": r"\.mackt",
            "description": "The PE was fixed by ImpREC",
            "severity": "uncommon",
        },
        {
            "rule": r"\.MaskPE",
            "description": "The PE is packed with MaskPE",
            "severity": "uncommon",
        },
        {
            "rule": r"MEW",
            "description": "The PE is packed with MEW",
            "severity": "uncommon",
        },
        {
            "rule": r"\.neolite?",
            "description": "The PE is packed with Neolite",
            "severity": "uncommon",
        },
        {
            "rule": r"\.nsp[012]",
            "description": "The PE is packed with NsPack",
            "severity": "uncommon",
        },
        {
            "rule": r"\.RLPack",
            "description": "The PE is packed with RLPack",
            "severity": "uncommon",
        },
        {
            "rule": r"(pe|PE)([Bb]undle|[cC][12]([TM]O)?|Compact2)",
            "description": "The PE is packed with PEBundle",
            "severity": "uncommon",
        },
        {
            "rule": r"PELOCKnt",
            "description": "This PE is packed with PELock",
            "severity": "uncommon",
        },
        {
            "rule": r"\.perplex",
            "description": "This PE is packed with Perplex",
            "severity": "uncommon",
        },
        {
            "rule": r"PESHiELD",
            "description": "This PE is packed with PEShield",
            "severity": "uncommon",
        },
        {
            "rule": r"\.petite",
            "description": "This PE is packed with Petite",
            "severity": "uncommon",
        },
        {
            "rule": r"ProCrypt",
            "description": "This PE is packed with ProCrypt",
            "severity": "uncommon",
        },
        {
            "rule": r".rmnet",
            "description": "This PE is packed with Ramnit",
            "severity": "uncommon",
        },
        {
            "rule": r"\.RPCrypt|Rcryptor",
            "description": "This PE is packed with RPCrypt",
            "severity": "uncommon",
        },
        {
            "rule": r"\.seau",
            "description": "This PE is packed with SeauSFX",
            "severity": "uncommon",
        },
        {
            "rule": r"\.spack",
            "description": "This PE is packed with Simple Pack (by bagie)",
            "severity": "uncommon",
        },
        {
            "rule": r"\.svkp",
            "description": "This PE is packed with SVKP",
            "severity": "uncommon",
        },
        {
            "rule": r"(\.?Themida)|(WinLicen)",
            "description": "This PE is packed with Themida",
            "severity": "uncommon",
        },
        {
            "rule": r"\.tsu(arch|stub)",
            "description": "This PE is packed with TSULoader",
            "severity": "uncommon",
        },
        {
            "rule": r"PEPACK!!",
            "description": "This PE is packed with PEPack",
            "severity": "uncommon",
        },
        {
            "rule": r"\.(Upack|ByDwing)",
            "description": "This PE is packed with Upack",
            "severity": "uncommon",
        },
        {
            "rule": r"\.vmp[012]",
            "description": "This PE is packed with VMProtect",
            "severity": "uncommon",
        },
        {
            "rule": r"VProtect",
            "description": "This PE is packed with VProtect",
            "severity": "uncommon",
        },
        {
            "rule": r"\.winapi",
            "description": "This PE was modified with API Override",
            "severity": "uncommon",
        },
        {
            "rule": r"_winzip_",
            "description": "This PE is a WinZip self-extractor",
            "severity": "info",
        },
        {
            "rule": r"\.WWPACK",
            "description": "This PE is packed with WWPACK",
            "severity": "uncommon",
        },
        {
            "rule": r"\.y(P|0da)",
            "description": "This PE is packed with Y0da",
            "severity": "uncommon",
        },
    ]

    def analyze(self):

        if "pe" not in self.artifacts.keys():
            self.logger.warn(
                "PE Info artifacts not found on sample %s" % self.sample["id"]
            )
            return False

        """ Triage Processing """

        # Check for evil imports
        self.check_evil_imports()

        # Check section entropy
        self.check_section_entropy()

        # Check resources
        self.check_resources()

        # Check known-packer sections
        self.check_known_packers()

        # Check for evil IOCs
        self.check_evil_iocs()

        """ Correlation Processing """
        self.check_ransomware()
        self.check_dropper()

    def check_evil_iocs(self):

        # Cryptocurrency wallet addresses on binaries are usually not good
        if len(self.iocs["bitcoin_addresses"]) > 0:

            wallet_addrs = ", ".join(set(self.iocs["bitcoin_addresses"]))

            self.add_indicator("string_cryptowallet_addr")
            self.add_flag(
                "This sample may be a ransomware",
                "The following cryptocurrency wallet addresses were identified: %s"
                % wallet_addrs,
                "evil_iocs",
                "suspicious",
            )

    def check_section_entropy(self):

        if "sections" not in self.artifacts["pe"]:
            return False

        for s in self.artifacts["pe"]["sections"]:
            if s["entropy"] >= EVIL_ENTROPY_THRESHOLD:
                self.add_indicator("%s_section_evil_entropy" % s["name"])
                self.add_flag(
                    "This sample may have encrypted or compressed data",
                    "Section %s has a suspicious entropy of %.4f"
                    % (s["name"], s["entropy"]),
                    "section_entropy",
                    "suspicious",
                    mitre_attack_id=[MA_DATA_ENCRYPTED, MA_DATA_COMPRESSED],
                )

    def check_resources(self):

        # Check resource entropy & size
        if "resources" not in self.artifacts["pe"]:
            return False

        total_resource_size = 0

        for r in self.artifacts["pe"]["resources"]:

            total_resource_size += r["size"]

            if r["entropy"] >= EVIL_ENTROPY_THRESHOLD:
                self.add_indicator("resource_evil_entropy")
                self.add_flag(
                    "This sample may have encrypted or compressed resources",
                    "Resource %s has a suspicious entropy of %.4f"
                    % (r["path"], r["entropy"]),
                    "resource_entropy",
                    "suspicious",
                    mitre_attack_id=[MA_DATA_ENCRYPTED, MA_DATA_COMPRESSED],
                )

        r_size_ratio = total_resource_size / self.sample["metadata"]["size"]

        if r_size_ratio >= EVIL_RES_SIZE_RATIO:
            self.add_indicator("resource_section_evil_size_ratio")
            self.add_flag(
                "This sample may be a dropper",
                "Resource section comprises %.2f%% of the binary"
                % (r_size_ratio * 100),
                "resource_size_ratio",
                "suspicious",
            )

    def check_ransomware(self):

        if not self.has_indicators(
            ["evil_import_crypto_api", "string_cryptowallet_addr"]
        ):
            return False

        self.add_indicator("ransomware")
        self.add_flag(
            "This sample is likely a ransomware",
            "Sample imports Microsoft's Cryptography API and has cryptocurrency wallet addresses referenced in the code",
            "ransomware",
            "malicious",
        )

    def check_dropper(self):

        if self.has_indicators(
            ["resource_section_evil_size_ratio", ".rsrc_section_evil_entropy"]
        ):
            self.add_indicator("dropper")
            self.add_flag(
                "This sample is likely a dropper",
                "Sample has a high-entropy resources section which comprises for most of the binary's size",
                "dropper",
                "malicious",
            )

    def check_known_packers(self):

        if "sections" not in self.artifacts["pe"]:
            return False

        has_packer = False

        for check in self.known_packer_sections:
            for section in self.artifacts["pe"]["sections"]:
                if re.match(check["rule"], section["name"]):
                    has_packer = True
                    self.add_flag(
                        "This sample was packed",
                        check["description"],
                        "known_packer_sections",
                        check["severity"],
                        mitre_attack_id=MA_SOFTWARE_PACKING,
                    )

        if has_packer:
            self.add_indicator("packed")

    def check_evil_imports(self):

        if "imports" not in self.artifacts["pe"]:
            return False

        import_list = []

        # Grab all import names from PE
        for import_entry in self.artifacts["pe"]["imports"]:
            if "imports" not in import_entry:
                self.logger.warn(
                    "Import list for dll %s is missing" % import_entry["name"]
                )
                continue

            for imp in import_entry["imports"]:
                import_list.append(imp["name"])

        # Iterate
        for group, info in self.evil_imports.items():
            matches = []
            for check in info["rules"]:
                for imp in import_list:
                    if re.match(check, imp):
                        matches.append(imp)

            # If we have matches, add flag
            min_matches = (
                info["min_match"] if "min_match" in info.keys() else IMPORT_MIN_MATCHES
            )
            if len(matches) >= min_matches:
                imp_names = ", ".join(matches)
                self.add_indicator("evil_import_%s" % group)
                self.add_flag(
                    "This sample contains functions commonly used by malware",
                    "%s: %s" % (info["description"], imp_names),
                    "suspicious_imports",
                    info["severity"],
                    mitre_attack_id=info["mitre_attack_id"],
                )

        # Check if total imports match RICH Header's 'Total Imports'
        if "rich_header" in self.artifacts["pe"]:
            for comp in self.artifacts["pe"]["rich_header"]["compids"]:
                if comp["type_id"] == RICH_COMPTYPE_TOTAL_IMPORTS:
                    if int(comp["count"]) != len(import_list):
                        self.add_indicator("rich_import_mismatch")
                        self.add_flag(
                            "This sample is packed or was manually edited",
                            "The number of imported functions (%d) is different than reported on the RICH header (%d)"
                            % (len(import_list), comp["count"]),
                            "rich_header_mismatch",
                            "suspicious",
                        )
