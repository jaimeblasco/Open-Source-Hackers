#!/usr/bin/env python

"""
Jaime Blasco
jaime.blasco@alienvault.com
(c) Alienvault, Inc. 2013

"""

from ctypes import c_int
from ctypes import c_void_p
from ctypes import c_long
from ctypes import windll
from ctypes import POINTER
from ctypes import wintypes

from structures import PROCESSENTRY32
from structures import MODULEENTRY32
from structures import THREADENTRY32

PROCESS_32_FIRST = windll.kernel32.Process32First
PROCESS_32_FIRST.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
PROCESS_32_FIRST.rettype = c_int

PROCESS_32_NEXT = windll.kernel32.Process32Next
PROCESS_32_NEXT.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
PROCESS_32_NEXT.rettype = c_int

MODULE_32_FIRST = windll.kernel32.Module32First
MODULE_32_FIRST.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
MODULE_32_FIRST.rettype = c_int

MODULE_32_NEXT = windll.kernel32.Module32Next
MODULE_32_NEXT.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
MODULE_32_NEXT.rettype = c_int

CREATETOOLHELP_32_SNAPSHOT = windll.kernel32.CreateToolhelp32Snapshot
CREATETOOLHELP_32_SNAPSHOT.reltype = c_long
CREATETOOLHELP_32_SNAPSHOT.argtypes = [c_int, c_int]

CLOSE_HANDLE = windll.kernel32.CloseHandle
CLOSE_HANDLE.argtypes = [c_void_p]
CLOSE_HANDLE.rettype = c_int

OPEN_PROCESS = windll.kernel32.OpenProcess
OPEN_PROCESS.argtypes = [c_void_p, c_int, c_long]
OPEN_PROCESS.rettype = c_long

OPEN_PROCESS_TOKEN = windll.advapi32.OpenProcessToken
OPEN_PROCESS_TOKEN.argtypes = (wintypes.HANDLE, wintypes.DWORD, \
POINTER(wintypes.HANDLE))
OPEN_PROCESS_TOKEN.restype = wintypes.BOOL

READ_PROCESS_MEMORY = windll.kernel32.ReadProcessMemory

WRITE_PROCESS_MEMORY = windll.kernel32.WriteProcessMemory

GET_LAST_ERROR = windll.kernel32.GetLastError
GET_LAST_ERROR.rettype = c_long

THREAD_32_FIRST = windll.kernel32.Thread32First
THREAD_32_FIRST.argtypes = [ c_void_p , POINTER(THREADENTRY32) ]
THREAD_32_FIRST.rettype = c_int

THREAD_32_NEXT = windll.kernel32.Thread32Next
THREAD_32_NEXT.argtypes = [ c_void_p , POINTER(THREADENTRY32) ]
THREAD_32_NEXT.rettype = c_int

MINI_DUMP_WRITER = windll.dbghelp.MiniDumpWriteDump

'''
BOOL WINAPI MiniDumpWriteDump(
  _In_  HANDLE hProcess,
  _In_  DWORD ProcessId,
  _In_  HANDLE hFile,
  _In_  MINIDUMP_TYPE DumpType,
  _In_  PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
  _In_  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
  _In_  PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);
'''

GETSYSTEMINFO = windll.kernel32.GetSystemInfo
GETSYSTEMINFO.argtypes = [ c_void_p ]

VIRTUALQUERYEX = windll.kernel32.VirtualQueryEx

'''
SIZE_T WINAPI VirtualQueryEx(
  _In_      HANDLE hProcess,
  _In_opt_  LPCVOID lpAddress,
  _Out_     PMEMORY_BASIC_INFORMATION lpBuffer,
  _In_      SIZE_T dwLength
);

'''

READ_PROCESS_MEMORY = windll.kernel32.ReadProcessMemory





