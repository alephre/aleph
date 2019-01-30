import re

from aleph.common.base import AnalyzerBase

class PEInfoAnalyzer(AnalyzerBase):

    name = 'pe_static_analyzer'
    mimetypes = ['application/x-dosexec']
    categories = ['suspicious_imports']

    # Mostly taken from <https://github.com/JusticeRage/Manalyze/blob/master/plugins/plugin_imports.cpp>
    evil_imports = {
        'anti_debug': {
            'description': 'Imports functions commonly used to detect/evade/deter debugging.',
            'severity': 'medium',
            'rules': [
                'FindWindow(A|W)',
                '(Zw|Nt)QuerySystemInformation',
                'DbgBreakPoint',
                'DbgPrint',
                'CheckRemoteDebuggerPresent',
                'CreateToolhelp32Snapshot',
                'Toolhelp32ReadProcessMemory',
                'OutputDebugString',
                'SwitchToThread',
                'NtQueryInformationProcess'
            ],
        },
        'vanilla_injection': {
            'description': 'Imports functions commonly used on vanilla code injection techniques.',
            'severity': 'medium',
            'rules': [
                '(Nt)?VirtualAlloc.*',
                '(Nt)?WriteProcessMemory',
                'CreateRemoteThread(Ex)?',
                '(Nt)?OpenProcess',
            ],
        },
        'process_hollowing': {
            'description': 'Imports functions commonly used on process hollowing code injection techniques.',
            'severity': 'medium',
            'rules': [
                '(Nt)?WriteProcessMemory',
                '(Nt)?WriteVirtualMemory',
                '(Wow64)?SetThreadContext',
                '(Nt)?ResumeThread',
                '(Nt)?SetContextThread',
            ],
        },
        'power_loader': {
            'description': 'Imports functions commonly used on power loader code injection techniques.',
            'severity': 'medium',
            'rules': [
            'FindWindow(A|W)',
            'GetWindowLong(A|W)'
            ],
        },
        'atom_bombing': {
            'description': 'Imports functions commonly used on atom bombing code injection techniques.',
            'severity': 'medium',
            'rules': [
                'GlobalAddAtom(A|W)',
                'GlobalGetAtomName(A|W)'
                'QueueUserAPC',
            ],
        },
        'process_doppelganging': {
            'description': 'Imports functions commonly used on process doppelganging code injection techniques.',
            'severity': 'medium',
            'rules': [
                'CreateTransaction',
                'CreateFileTransacted',
                'RollbackTransaction',
                '(Nt)?WriteFile',
            ],
        },
        'keylogger_api': {
            'description': 'Imports functions commonly used by keyloggers.',
            'severity': 'high',
            'rules': [
                'SetWindowsHook(Ex)?',
                'GetAsyncKeyState',
                'GetForegroundWindow',
                'AttachThreadInput',
                'CallNextHook(Ex)?',
                'MapVirtualKey(A|W|Ex)',
            ],
        },
        'raw_socket_api': {
            'description': 'Imports functions to handle raw sockets.',
            'severity': 'medium',
            'rules': [
                'accept',
                'bind',
                'connect',
                'recv',
                'send',
                'gethost(by)?name',
                'inet_addr',
            ],
        },
        'http_api': {
            'description': 'Imports functions for HTTP communication.',
            'severity': 'low',
            'rules': [
                'Internet.*',
                'URL(Download|Open).*',
                'WinHttp.*',
            ],
        },
        'registry_api': {
            'description': 'Imports functions that alter the Windows Registry.',
            'severity': 'medium',
            'rules': [
                'Reg.*(Key|Value).*',
                'SH.*(Reg|Key).*',
                'SHQueryValueEx(A|W)',
                'SHGetValue(A|W)',
            ],
        },
        'process_creation_api': {
            'description': 'Imports functions commonly used to create processes.',
            'severity': 'low',
            'rules': [
                '(Nt)?CreateProcess.*',
                'system',
                'WinExec',
                'ShellExecute(A|W)',
            ],
        },
        'process_manipulation_api': {
            'description': 'Imports functions commonly used for manipulating processes.',
            'severity': 'high',
            'rules': [
                'EnumProcess.*',
                '(Nt)?OpenProcess',
                '(Nt)?(Read|Write)ProcessMemory',
                'Process32(First|Next)(A|W)?',
            ],
        },
        'service_manipulation_api': {
            'description': 'Imports functions commonly used on Windows Services manipulation.',
            'severity': 'medium',
            'rules': [
                'OpenSCManager(A|W)',
                '(Open|Control|Create|Delete)Service(A|W)?',
                'QueryService.*',
                'ChangeServiceConfig(A|W)',
                'EnumServicesStatus(Ex)?(A|W)',
            ],
        },
        'privilege_api': {
            'description': 'Imports functions commonly used on privilege escalation.',
            'severity': 'high',
            'rules': [
                'AdjustTokenPrivileges',
                'IsNTAdmin',
                'LsaEnumerateLogonSessions',
                'SamQueryInformationUser',
                'SamIGetPrivateData',
                'SfcTerminateWatcherThread',
                '(Zw)?OpenProcessToken(Ex)?',
                '(Zw)?DuplicateToken(Ex)?',
                '(SHTest|Check)TokenMembership',
            ],
        },
        'dacl_api': {
            'description': 'Imports DACL functions, used to change security attributes from objects.',
            'severity': 'low',
            'rules': [
                'SetKernelObjectSecurity'
                'SetFileSecurity(A|W)'
                'SetNamedSecurityInfo(A|W)'
                'SetSecurityInfo',
            ],
        },
        'dynamic_import': {
            'description': 'Imports functions that load libraries dynamically.',
            'severity': 'low',
            'rules': [
                '(Co)?LoadLibrary(Ex)?(A|W)',
                'GetProcAddress',
                'LdrLoadDll',
                'MmGetSystemRoutineAddress',
            ],
        },
        'packer_api': {
            'description': 'Imports functions commonly used on packers.',
            'severity': 'low',
            'rules': [
                '(Nt)?VirtualAlloc(Ex)?',
                '(Nt)?VirtualProtect(Ex)?',
            ],
        },
        'temporary_files': {
            'description': 'Imports functions to create temporary files.',
            'severity': 'low',
            'rules': [
                'GetTempPath(A|W)',
                '(Create|Write)File(A|W)',
            ],
        },
        'hdd_enumeration': {
            'description': 'Imports functions commonly used to enumerate disk drives.',
            'severity': 'low',
            'rules': [
                'GetVolumeInformation(ByHandle)?(A|W)',
                'GetDriveType(A|W)',
                'GetLogicalDriveStrings(A|W)',
            ],
        },
        'driver_enumeration': {
            'description': 'Imports functions commonly used to enumerate drivers.',
            'severity': 'low',
            'rules': [
                'EnumDeviceDrivers',
                'GetDeviceDriver.*'
            ],
        },
        'eventlog_deletion': {
            'description': 'Imports functions used to delete Windows Event Logs.',
            'severity': 'high',
            'rules': [
                'EvtClearLog',
                'ClearEventLog(A|W)',
            ],
        },
        'screenshot_api': {
            'description': 'Imports functions commonly used to capture the device screen.',
            'severity': 'medium',
            'rules': [
                'CreateCompatibleDC',
                'GetDC(Ex)?',
                'FindWindow(A|W)',
                'PrintWindow',
                'BitBlt',
            ],
        },
        'audio_api': {
            'description': 'Imports functions from the Audio API that could be used to intercept conversations.',
            'severity': 'medium',
            'rules': [
                'waveInOpen',
                'DirectSoundCaptureCreate.*'
            ],
        },
        'shutdown_functions': {
            'description': 'Imports functions used to shutdown the OS.',
            'severity': 'low',
            'rules': [
                'Initiate(System)?Shutdown(Ex)?(A|W)',
                'LockWorkStation',
                'ExitWindows(Ex)?',
            ],
        },
        'networking_api': {
            'description': 'Imports functions that configures networking.',
            'severity': 'low',
            'rules': [
                '(Un)?EnableRouter',
                'SetAdapterIpAddress',
                'SetIp(Forward|Net|Statistics|TTL).*',
                'SetPerTcp(6)?ConnectionEStats',
            ],
        },
    }

    def analyze(self, sample):

        artifacts = sample['metadata']['artifacts']

        if not 'pe_info' in artifacts.keys():
            self.logger.warn('PE Info artifacts not found on sample %s' % sample['id'])
            return False

        if not 'imports' in artifacts['pe_info']:
            self.logger.warn('Imports not found on PE Info\'s artifacts on sample %s' % sample['id'])
            return False

        pe_imports = artifacts['pe_info']['imports']
        import_list = []

        # Grab all import names from PE
        for dllname, imports in pe_imports.items():
            for imp in imports:
                import_list.append(imp['name'])
        
        # Iterate 
        for group, info in self.evil_imports.items():
            matches = []
            for check in info['rules']:
                for imp in import_list:
                    if re.match(check, imp):
                        matches.append(imp)

            # If we have matches, add flag
            if len(matches) > 0:
                imp_names = ', '.join(matches)
                self.add_flag('%s (%s)' % (info['description'], imp_names), 'suspicious_imports', info['severity'])
