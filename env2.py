import logging
import ctypes
import platform
from ctypes import (byref, Structure, c_void_p, sizeof, c_ubyte, c_ulonglong,
                    c_ushort, create_unicode_buffer, c_ulong, c_size_t)


def _windows_function(fn, success_on_zero, exception_on_fail=True):
    '''
    This does some basic error checking based on the return value.  Not all functions
    will use GetLastError() to report errors, so you may still have to manually check
    the return value.

    :param fn: The ctypes function that you wish to wrap.

    :param success_on_zero: A zero return indicates a successful run.

    :exception_on_fail: Raise an exception when an error is detected.
    '''
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
OpenProcess = _windows_function(ctypes.windll.kernel32.OpenProcess,
                               success_on_zero=False)
IsWow64Process = _windows_function(ctypes.windll.kernel32.IsWow64Process,
                                  success_on_zero=False)


def is_wow64(handle):
    is_wow64 = ctypes.c_bool(False)

    IsWow64Process(handle, byref(is_wow64))
    return is_wow64.value

if is_wow64(ctypes.windll.kernel32.GetCurrentProcess()):
    QueryInformationProcess = _windows_function(
        ctypes.windll.ntdll.NtWow64QueryInformationProcess64, success_on_zero=True)
    ReadProcessMemory = _windows_function(ctypes.windll.ntdll.NtWow64ReadVirtualMemory64,
                                         success_on_zero=True)
    QueryVirtualMemory = _windows_function(
        ctypes.windll.ntdll.NtWow64QueryVirtualMemory64, success_on_zero=True)

    class arch_pointer(Structure):
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

            difference = arch_pointer()

            difference.low = result & 0xFFFFFF
            difference.high = result >> 32

            return difference

    size_t = c_ulonglong

else:
    QueryInformationProcess = _windows_function(
        ctypes.windll.ntdll.NtQueryInformationProcess, success_on_zero=True)
    ReadProcessMemory = _windows_function(ctypes.windll.ntdll.NtReadVirtualMemory,
                                         success_on_zero=False)
    QueryVirtualMemory = _windows_function(ctypes.windll.ntdll.NtQueryVirtualMemory,
                                          success_on_zero=True)

    arch_pointer = c_void_p
    size_t = c_size_t


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('BaseAddress', arch_pointer),
        ('AllocationBase', arch_pointer),
        ('AllocationProtect', c_ulong),
        ('RegionSize', size_t),
        ('State', c_ulong),
        ('Protect', c_ulong),
        ('Type', c_ulong)
    ]


class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('Reserved1', arch_pointer),
        ('PebBaseAddress', arch_pointer),
        ('Reserved2', arch_pointer * 2),
        ('UniqueProcessId', arch_pointer),
        ('Reserved3', arch_pointer)
    ]


class UNICODE_STRING(Structure):
    _fields_ = [
        ('Length', c_ushort),
        ('MaximumLength', c_ushort),
        ('String', arch_pointer),
    ]


def has_read_access(handle, address):
    mbi = MEMORY_BASIC_INFORMATION()

    size = size_t()
    mbi_size = size_t(sizeof(mbi))

    # We use QueryVirtualMemory since there's a 64 bit accessible function on emulated
    #   programs.  It should return the MEMORY_BASIC_INFORMATION containing the region
    #   size.
    QueryVirtualMemory(handle, address, 0, byref(mbi), mbi_size, byref(size))

    # Even though we put in a specific address, the mbi gives us the entire region size, so
    #   So we get the remaining region size by subtracting the address we put in by the
    #   BaseAddress (basically the start of the nearest page border)
    return mbi.RegionSize - long(address - mbi.BaseAddress)


def find_env(pid):
    # We open the process with permissions that allow us to read the appropriate memory
    #   blocks.
    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

    if not handle:
        raise Exception('OpenProcess on {0} failed.'.format(pid))

    # Not sure if this is the best way or not.
    is64bit = platform.machine() == 'AMD64'

    # Because pointers are twice as large in 64 bits, the offsets are different
    ProcessParametersOffset = 0x20 if is64bit else 0x10
    EnvOffset = 0x7c if is64bit else 0x48

    size = size_t()

    peb_size = size_t(ProcessParametersOffset + 8)
    peb = (c_ubyte * peb_size.value)()
    pp_size = size_t(EnvOffset + 16)
    pp = (c_ubyte * pp_size.value)()


    # The process basic information structure, when populated contains a pointer to
    #   the PEB (process environment block) which contains pointers to various environment
    #   details including the command line used to execute the program.
    pbi = PROCESS_BASIC_INFORMATION()

    QueryInformationProcess(handle, 0, byref(pbi), sizeof(pbi), None)

    # We're reading the PEB into our PEB byte block.
    ReadProcessMemory(handle, pbi.PebBaseAddress, byref(peb), peb_size, byref(size))

    # At the correct offset is a pointer to the ProcessParameters structure which contains
    #   the environment and the command line information.
    parameters = (c_ubyte * 8)(*peb[ProcessParametersOffset:])

    param_addr = arch_pointer.from_buffer_copy(parameters)
    ReadProcessMemory(handle, param_addr, byref(pp), pp_size, byref(size))

    # The environment string is in a UNICODE_STRING structure which, for some reason,
    #   doesn't contain the correct size of the string length.  For this reason for now we
    #   just copy the rest of the region (expensive) and parse until we see 2 null
    #   characters in a row.
    env = (c_ubyte * 16)(*pp[EnvOffset:])
    environment = UNICODE_STRING.from_buffer_copy(env)

    region_size = has_read_access(handle, environment.String)

    env_str = create_unicode_buffer('\000' * (region_size / 2))
    env_str_size = size_t(region_size)

    c_ulong(ReadProcessMemory(handle, environment.String, byref(env_str),
                              env_str_size, byref(size)))

    buffers = []
    start = 0

    # Each env variable/value is separated by a null character.  Two of these denote the end
    #   of the environment variables section.
    for idx, v in enumerate(env_str):
        if ord(v) == 0:
            if start - idx:
                buffers.append(env_str[start:idx])
                start = idx + 1
            else:
                break

    return dict([b.encode('ascii', 'ignore').split('=', 1) for b in buffers])
