#!/usr/bin/env python

"""
Jaime Blasco
jaime.blasco@alienvault.com
(c) Alienvault, Inc. 2013

"""

"""
Ctypes structures module.
"""

from ctypes import c_long, c_uint, c_char, c_ushort
from ctypes import Structure
from ctypes import *

BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char)
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong


class PROCESSENTRY32(Structure):
    """
    Describes an entry from a list of the processes residing in the system\
address space when a snapshot was taken.
    """

    _fields_ = [
        ('dwSize', c_uint),
        ('cntUsage', c_uint),
        ('th32ProcessID', c_uint),
        ('th32DefaultHeapID', c_uint),
        ('th32ModuleID', c_uint),
        ('cntThreads', c_uint),
        ('th32ParentProcessID', c_uint),
        ('pcPriClassBase', c_long),
        ('dwFlags', c_uint),
        ('szExeFile', c_char * 260),
        ('th32MemoryBase', c_long),
        ('th32AccessKey', c_long)
    ]


class MODULEENTRY32(Structure):
    """
    Describes an entry from a list of the modules belonging to the specified\
process.
    """

    _fields_ = [("dwSize", c_uint),
        ("th32ModuleID", c_uint),
        ("th32ProcessID", c_uint),
        ("GlblcntUsage", c_uint),
        ("ProccntUsage", c_uint),
        ("modBaseAddr", c_uint),
        ("modBaseSize", c_uint),
        ("hModule", c_uint),
        ("szModule", c_char * 256),
        ("szExePath", c_char * 260),
    ]


class THREADENTRY32(Structure):
    """
    Describes an entry from a list of the threads executing in the system\
when a snapshot was taken.
    """

    _fields_ = [
        ('dwSize', c_uint),
        ('cntUsage', c_uint),
        ('th32ThreadID', c_uint),
        ('th32OwnerProcessID', c_uint),
        ('tpBasePri', c_uint),
        ('tpDeltaPri', c_uint),
        ('dwFlags', c_uint),
    ]


class MINIDUMP_EXCEPTION_INFORMATION(Structure):
    """
    Contains the exception information written to the minidump file by the MiniDumpWriteDump function.
    """

    _fields_ = [
        ('ThreadId', c_uint),
        ('ExceptionPointers', c_uint),
        ('ClientPointers', c_uint),
    ]


class TH32CS_CLASS(object):
    """
    THREAD global values.
    """

    INHERIT = 0x80000000
    SNAPHEAPLIST = 0x00000001
    SNAPMODULE = 0x00000008
    SNAPMODULE32 = 0x00000010
    SNAPPROCESS = 0x00000002
    SNAPTHREAD = 0x00000004
    ALL = 0x001F03FF


class PROCESS_CLASS(object):
    """
    PROCESS global values.
    """

    CREATE_PROCESS = 0x0080
    CREATE_THREAD = 0x0002
    DUP_HANDLE = 0x0040
    QUERY_INFORMATION = 0x0400
    QUERY_LIMITED_INFORMATION = 0x1000
    SET_INFORMATION = 0x0200
    SET_QUOTA = 0x0100
    SUSPEND_RESUME = 0x0800
    TERMINATE = 0x0001
    VM_OPERATION = 0x0008
    VM_READ = 0x0010
    VM_WRITE = 0x0020
    SYNCHRONIZE = 0x00100000L
    ALL = (0x000F0000 | 0x00100000 | 0xFFF)


class TOKEN_INFORMATION_CLASS(object):
    """
    TOKEN global values.
    """

    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3
    TokenOwner = 4
    TokenPrimaryGroup = 5
    TokenDefaultDacl = 6
    TokenSource = 7
    TokenType = 8
    TokenImpersonationLevel = 9
    TokenStatistics = 10
    TokenRestrictedSids = 11
    TokenSessionId = 12
    TokenGroupsAndPrivileges = 13
    TokenSessionReference = 14
    TokenSandBoxInert = 15
    TokenAuditPolicy = 16
    TokenOrigin = 17
    TokenElevationType = 18
    TokenLinkedToken = 19
    TokenElevation = 20
    TokenHasRestrictions = 21
    TokenAccessInformation = 22
    TokenVirtualizationAllowed = 23
    TokenVirtualizationEnabled = 24
    TokenIntegrityLevel = 25
    TokenUIAccess = 26
    TokenMandatoryPolicy = 27
    TokenLogonSid = 28
    MaxTokenInfoClass = 29


class MINIDUMP_TYPES_CLASS(object):
    """
    MINIDUMP types
    """

    MiniDumpNormal = 0x00000000
    MiniDumpWithDataSegs = 0x00000001
    MiniDumpWithFullMemory = 0x00000002
    MiniDumpWithHandleData = 0x00000004
    MiniDumpFilterMemory = 0x00000008
    MiniDumpScanMemory = 0x00000010
    MiniDumpWithUnloadedModules = 0x00000020
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040
    MiniDumpFilterModulePaths = 0x00000080
    MiniDumpWithProcessThreadData = 0x00000100
    MiniDumpWithPrivateReadWriteMemory = 0x00000200
    MiniDumpWithoutOptionalData = 0x00000400
    MiniDumpWithFullMemoryInfo = 0x00000800
    MiniDumpWithThreadInfo = 0x00001000
    MiniDumpWithCodeSegs = 0x00002000


# Supporting struct for the SYSTEM_INFO_UNION union
class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture",    DWORD),
        ("wReserved",                 DWORD),]


# Supporting union for the SYSTEM_INFO struct
class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId",    DWORD),
        ("sProcStruc", PROC_STRUCT),]

class SYSTEM_INFO(Structure):
    """
    kernel32.GetSystemInfo()
    """
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
]
