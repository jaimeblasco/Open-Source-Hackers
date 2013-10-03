#!/usr/bin/env python

"""
Jaime Blasco
jaime.blasco@alienvault.com
(c) Alienvault, Inc. 2013

"""

from ctypes import sizeof
from ctypes import byref
from ctypes import pointer
import copy
import win32security
from ctypes import c_long , c_int , c_uint , c_char , c_ubyte , c_char_p , c_void_p, c_ulong, create_string_buffer

from utils import duplicate

from constants.defines import PROCESS_32_FIRST, PROCESS_32_NEXT
from constants.defines import CREATETOOLHELP_32_SNAPSHOT
from constants.defines import CLOSE_HANDLE
from constants.defines import OPEN_PROCESS
from constants.defines import MODULE_32_FIRST, MODULE_32_NEXT
from constants.defines import GET_LAST_ERROR
from constants.defines import THREAD_32_FIRST, THREAD_32_NEXT
from constants.defines import MINI_DUMP_WRITER
from constants.defines import GETSYSTEMINFO
from constants.defines import READ_PROCESS_MEMORY
from constants.defines import VIRTUALQUERYEX

from constants.structures import PROCESS_CLASS
from constants.structures import PROCESSENTRY32
from constants.structures import TH32CS_CLASS
from constants.structures import MODULEENTRY32
from constants.structures import THREADENTRY32
from constants.structures import MINIDUMP_TYPES_CLASS
from constants.structures import SYSTEM_INFO
from constants.structures import MEMORY_BASIC_INFORMATION

import win32security, win32con, win32api, win32file, pywintypes
import sys
import yara
import os
from optparse import OptionParser


rules = None

system_info = SYSTEM_INFO()
GETSYSTEMINFO(byref(system_info))

def ListProcesses():
        result = []
        hProcessSnap = c_void_p(0)
        hProcessSnap = CREATETOOLHELP_32_SNAPSHOT( TH32CS_CLASS.SNAPPROCESS , 0 )


        pe32 = PROCESSENTRY32()
        pe32.dwSize = sizeof( PROCESSENTRY32 )
        ret = PROCESS_32_FIRST( hProcessSnap , pointer( pe32 ) )

        while ret :
                result.append(duplicate(pe32))
                ret = PROCESS_32_NEXT( hProcessSnap, pointer(pe32) )

        CLOSE_HANDLE(hProcessSnap)
        return result


def ListProcessModules( ProcessID ):
        result = []
        hModuleSnap = c_void_p(0)
        me32 = MODULEENTRY32()
        me32.dwSize = sizeof( MODULEENTRY32 )
        hModuleSnap = CREATETOOLHELP_32_SNAPSHOT( TH32CS_CLASS.SNAPMODULE, ProcessID )

        ret = MODULE_32_FIRST( hModuleSnap, pointer(me32) )
        if ret == 0 :
                errmsg =  'ListProcessModules() Error on Module32First[%d]' % GET_LAST_ERROR()
                print errmsg
                CLOSE_HANDLE( hModuleSnap )

        while ret :
                result.append(duplicate(me32))

                ret = MODULE_32_NEXT( hModuleSnap , pointer(me32) )

        CLOSE_HANDLE( hModuleSnap )
        return result

def ListProcessThreads( ProcessID ):
        result = []
        hThreadSnap = c_void_p(0)
        te32 = THREADENTRY32 ()
        te32.dwSize = sizeof(THREADENTRY32 )

        hThreadSnap = CREATETOOLHELP_32_SNAPSHOT( TH32CS_CLASS.SNAPTHREAD, 0 )

        ret = THREAD_32_FIRST( hThreadSnap, pointer(te32) )

        if ret == 0 :
                errmsg = 'ListProcessThreads() Error on Thread32First[%d]' % GET_LAST_ERROR()
                CLOSE_HANDLE( hThreadSnap )

        while ret :
                if te32.th32OwnerProcessID == ProcessID :
                        result.append(duplicate(te32))

                ret = THREAD_32_NEXT( hThreadSnap, pointer(te32) )

        CLOSE_HANDLE( hThreadSnap )
        return result

def AdjustPrivilege( priv ):
    flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
    htoken =  win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
    id = win32security.LookupPrivilegeValue(None, priv)
    newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
    win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)

def DumpProcess(ProcessID, rules):
    AdjustPrivilege("seDebugPrivilege")

    #PROCESS_ALL_ACCESS

    pHandle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ , 0, ProcessID)

    fHandle = win32file.CreateFile("%d.tmp" % ProcessID,
                               win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                               win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                               None,
                               win32file.CREATE_ALWAYS,
                               win32file.FILE_ATTRIBUTE_NORMAL,
                               None)



    ret = MINI_DUMP_WRITER(pHandle.handle,
                           ProcessID,
                           fHandle.handle,
                           MINIDUMP_TYPES_CLASS.MiniDumpWithFullMemory,
                           None,
                           None,
                           None)


    win32api.CloseHandle(pHandle)
    win32api.CloseHandle(fHandle)
    matches = None
    try:
        matches = rules.match("%d.tmp" % ProcessID)
    except:
        pass
    if matches:
        for m in matches:
            print m
    os.remove("%d.tmp" % ProcessID)


def ReadProcessMemory(ProcessID, rules):


    base = 0
    memory_basic_information = MEMORY_BASIC_INFORMATION()
    AdjustPrivilege("seDebugPrivilege")
    pHandle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ | win32con.PROCESS_VM_OPERATION , 0, ProcessID)

    while VIRTUALQUERYEX(pHandle.handle, base, byref(memory_basic_information), sizeof(memory_basic_information)) > 0:
        count = c_ulong(0)
        #MEM_COMMIT && MEM_PRIVATE
        #if memory_basic_information.State == 0x1000 and memory_basic_information.Type == 0x20000:
        try:
            buff = create_string_buffer(memory_basic_information.RegionSize)
            if READ_PROCESS_MEMORY(pHandle.handle, base, buff, memory_basic_information.RegionSize, byref(count)):
                #print buff.raw
                matches = rules.match(data=buff.raw)
                for m in matches:
                    print m, "0x%x" % memory_basic_information.BaseAddress
        except:
            pass
        base += memory_basic_information.RegionSize

    win32api.CloseHandle(pHandle)
    #base += system_info.dwPageSize



def main():
    parser = OptionParser()
    parser.add_option("-l", "--list", dest="list", help="List active processes", default=False, action='store_true')
    parser.add_option("-p", "--pid", dest="pid", help="Process PID", metavar="FILE")
    parser.add_option("-a", "--all", dest="all", help="Apply to all the processes", default=False, action='store_true')
    parser.add_option("-m", "--match", dest="match", help="Run Yara against selected process", default=False, action='store_true')
    parser.add_option("-y", "--yarafile", dest="yarafile", help="Input Yara's' rule file", metavar="FILE")
    parser.add_option("-r", "--readprocessmemory", dest="readprocessmemory", help="Use ReadProcessMemory to access the process memory'", default=False, action='store_true')
    parser.add_option("-d", "--minidump", dest="minidump", help="Use MiniDumpWriter to access the process memory'", default=False, action='store_true')


    (opts, args) = parser.parse_args()

    if opts.__dict__['list']:
        procs = ListProcesses()
        print "PID\tName"
        for p in procs:
            print "%d\t%s" % (p.th32ProcessID, p.szExeFile)
        sys.exit(1)

    if opts.__dict__['yarafile']:
        if not os.path.isfile(opts.__dict__['yarafile']):
            print "Error accesing Yara's rule file"
            sys.exit(0)
        try:
            rules = yara.compile(opts.__dict__['yarafile'], includes=False)
        except yara.Error:
            print "Error in Yara's rule file"

    if opts.__dict__['match'] and not opts.__dict__['yarafile']:
        print "You need to specify a Yara rules file"
        sys.exit(0)

    if opts.__dict__['match'] and not (opts.__dict__['pid'] or  opts.__dict__['all']):
        print "You need to specify a process PID"
        sys.exit(0)

    if opts.__dict__['match'] and opts.__dict__['readprocessmemory']:
        if opts.__dict__['all']:
            procs = ListProcesses()
            for p in procs:
                print "%d\t%s" % (p.th32ProcessID, p.szExeFile)
                if p.th32ProcessID != 0:
                    ReadProcessMemory(p.th32ProcessID, rules)
        else:
            ReadProcessMemory(int(opts.__dict__['pid']), rules)
        sys.exit(0)

    if opts.__dict__['match'] and opts.__dict__['minidump']:
        if opts.__dict__['all']:
            procs = ListProcesses()
            for p in procs:
                print "%d\t%s" % (p.th32ProcessID, p.szExeFile)
                if p.th32ProcessID != 0:
                    DumpProcess(p.th32ProcessID, rules)
        else:
            DumpProcess(int(opts.__dict__['pid']), rules)
        sys.exit(0)


if __name__ == "__main__":
    main()

'''
sys.exit(0)
for p in procs:
    print p.th32ProcessID,p.szExeFile
    modules = ListProcessModules(p.th32ProcessID)
    for m in modules:
        print m.szModule,m.szExePath
    threads = ListProcessThreads(p.th32ProcessID)
    for t in threads:
        print t.th32ThreadID


'''
