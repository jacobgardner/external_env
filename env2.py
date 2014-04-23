import logging
import ctypes
import platform
from ctypes import (byref, Structure, c_uint64, c_void_p, sizeof, c_ubyte, c_ulonglong,
                    c_ushort, create_unicode_buffer, c_ulong)
from binascii import hexlify


def windows_function(fn, success_on_zero, exception_on_fail=True):
    def wrapped_fn(*args, **kwargs):
        success = fn(*args, **kwargs)

        # XOR
        if bool(success_on_zero) == bool(success):
            # Error
            err = ctypes.windll.kernel32.GetLastError()

            if not err:
                return success

            err_msg = ctypes.c_char_p()
            ctypes.windll.kernel32.FormatMessageA(
                0x00000100 | 0x00000200 | 0x00001000, None, err, 0, byref(err_msg), 0, None)

            logging.error('{0} raised {1} - {2}'.format(fn.__name__, err, err_msg.value))
            if exception_on_fail:
                raise WindowsError('{0} raised {1} - {2}'.format(fn.__name__, err, err_msg.value))

        return success

    return wrapped_fn

# Windows Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Windows Methods
OpenProcess = windows_function(ctypes.windll.kernel32.OpenProcess,
                               success_on_zero=False)
IsWow64Process = windows_function(ctypes.windll.kernel32.IsWow64Process,
                                  success_on_zero=False)


def is_wow64(handle):
    is_wow64 = ctypes.c_bool(False)

    IsWow64Process(handle, byref(is_wow64))
    return is_wow64.value

if is_wow64(ctypes.windll.kernel32.GetCurrentProcess()):
    QueryInformationProcess = windows_function(
        ctypes.windll.ntdll.NtWow64QueryInformationProcess64, success_on_zero=True)
    ReadProcessMemory = windows_function(ctypes.windll.ntdll.NtWow64ReadVirtualMemory64,
                                         success_on_zero=True)
    QueryVirtualMemory = windows_function(
        ctypes.windll.ntdll.NtWow64QueryVirtualMemory64, success_on_zero=True)

    class pvoid_64(Structure):
        _fields_ = [
            ('low', c_void_p),
            ('high', c_void_p)
        ]

        def __long__(self):
            low = self.low or 0
            high = self.high or 0
            return long(low) + long(high << 32)

        def __hex__(self):
            return hex(long(self))

        def __sub__(lhs, rhs):
            result = long(lhs) - long(rhs)

            difference = pvoid_64()

            difference.low = result & 0xFFFFFF
            difference.high = result >> 32

            return difference

    class PROCESS_BASIC_INFORMATION(Structure):
        _fields_ = [
            ('Reserved1', pvoid_64),
            ('PebBaseAddress', pvoid_64),
            ('Reserved2', pvoid_64 * 2),
            ('UniqueProcessId', c_uint64),
            ('Reserved3', pvoid_64)
        ]

    class UNICODE_STRING(Structure):
        _fields_ = [
            ('Length', c_ushort),
            ('MaximumLength', c_ushort),
            ('String', pvoid_64),
        ]

    class MEMORY_BASIC_INFORMATION(Structure):
        _fields_ = [
            ('BaseAddress', pvoid_64),
            ('AllocationBase', pvoid_64),
            ('AllocationProtect', c_ulong),
            ('RegionSize', c_ulonglong),
            ('State', c_ulong),
            ('Protect', c_ulong),
            ('Type', c_ulong)
        ]

else:
    QueryInformationProcess = windows_function(
        ctypes.windll.ntdll.NtQueryInformationProcess, success_on_zero=True)
    ReadProcessMemory = windows_function(ctypes.windll.kernel32.ReadProcessMemory,
                                         success_on_zero=False)

    class PROCESS_BASIC_INFORMATION(Structure):
        _fields_ = [
            ('Reserved1', c_void_p),
            ('PebBaseAddress', c_void_p),
            ('Reserved2', c_void_p * 2),
            ('UniqueProcessId', c_void_p),
            ('Reserved3', c_void_p)
        ]


def has_read_access(handle, address):
    mbi = MEMORY_BASIC_INFORMATION()

    size = c_ulonglong()
    mbi_size = c_ulonglong(sizeof(mbi))

    QueryVirtualMemory(handle, address, 0, byref(mbi), mbi_size, byref(size))

    return mbi.RegionSize - long(address - mbi.BaseAddress)


def find_env(pid):
    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

    if not handle:
        raise Exception('OpenProcess on {0} failed.'.format(pid))

    is64bit = platform.machine() == 'AMD64'

    ProcessParametersOffset = 0x20 if is64bit else 0x10
    EnvOffset = 0x7c if is64bit else 0x48

    size = c_ulonglong()

    peb_size = c_ulonglong(ProcessParametersOffset + 8)
    peb = (c_ubyte * peb_size.value)()
    pp_size = c_ulonglong(EnvOffset + 16)
    pp = (c_ubyte * pp_size.value)()

    pbi = PROCESS_BASIC_INFORMATION()

    QueryInformationProcess(handle, 0, byref(pbi), sizeof(pbi), None)

    ReadProcessMemory(handle, pbi.PebBaseAddress, byref(peb), peb_size, byref(size))

    parameters = (c_ubyte * 8)(*peb[ProcessParametersOffset:])

    param_addr = pvoid_64.from_buffer_copy(parameters)
    ReadProcessMemory(handle, param_addr, byref(pp), pp_size, byref(size))


    env = (c_ubyte * 16)(*pp[EnvOffset:])
    environment = UNICODE_STRING.from_buffer_copy(env)

    region_size = has_read_access(handle, environment.String)

    env_str = create_unicode_buffer('\000' * (region_size / 2))
    env_str_size = c_ulonglong(region_size)

    ret_code = c_ulong(ReadProcessMemory(handle, environment.String, byref(env_str), env_str_size, byref(size)))

    buffers = []
    start = 0

    for idx, v in enumerate(env_str):
        if ord(v) == 0:
            if start - idx:
                buffers.append(env_str[start:idx])
                start = idx + 1
            else:
                break

    return dict([b.encode('ascii', 'ignore').split('=', 1) for b in buffers])
