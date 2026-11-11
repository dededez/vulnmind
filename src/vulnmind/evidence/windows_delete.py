"""Delete one hash-verified file by handle while pinning every parent directory.

No path unlink or recursive deletion. The caller holds the evidence DB lock.
Non-cooperating database writers remain outside the local operator trust model.
"""
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path


def delete_verified(root, relative, digest, *, cutoff):
    if os.name != 'nt':
        raise RuntimeError('handle-based evidence deletion currently requires Windows')
    root = Path(root).absolute()
    path = root / relative
    if not path.is_relative_to(root) or '..' in Path(relative).parts or Path(relative).is_absolute():
        raise ValueError('invalid evidence path')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    info = kernel.GetFileInformationByHandleEx
    info.argtypes = [wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    read = kernel.ReadFile
    read.argtypes = [wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
    setinfo = kernel.SetFileInformationByHandle
    setinfo.argtypes = [wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    class Attributes(ctypes.Structure):
        _fields_=[('attributes',wintypes.DWORD),('tag',wintypes.DWORD)]
    class Basic(ctypes.Structure):
        _fields_=[('created',ctypes.c_longlong),('accessed',ctypes.c_longlong),('written',ctypes.c_longlong),
                  ('changed',ctypes.c_longlong),('attributes',wintypes.DWORD)]
    handles=[]
    def opened(value, access, share, flags):
        handle=create(str(value),access,share,None,3,flags,None)
        if handle == ctypes.c_void_p(-1).value:
            raise OSError('could not exclusively pin evidence path')
        handles.append(handle)
        attrs=Attributes()
        if not info(handle,9,ctypes.byref(attrs),ctypes.sizeof(attrs)) or attrs.attributes & 0x400:
            raise OSError('linked or unreadable evidence path')
        return handle
    try:
        # Pin from volume root down: a parent cannot be renamed or replaced
        # after checking it and before opening the next component.
        for directory in [*reversed(path.parent.parents), path.parent]:
            opened(directory,0x80,3,0x02000000|0x00200000)
        handle=opened(path,0x80000000|0x10000,1,0x00200000)
        basic=Basic()
        if not info(handle,0,ctypes.byref(basic),ctypes.sizeof(basic)):
            raise OSError('file timestamp unavailable')
        if basic.written/10000000-11644473600 > cutoff:
            return False
        buffer=ctypes.create_string_buffer(65536)
        count=wintypes.DWORD()
        hashed=hashlib.sha256()
        size=0
        while True:
            if not read(handle,buffer,len(buffer),ctypes.byref(count),None):
                raise OSError('evidence read failed')
            if not count.value:
                break
            size+=count.value
            if size>50000000:
                raise ValueError('evidence file exceeds deletion limit')
            hashed.update(buffer.raw[:count.value])
        if hashed.hexdigest()!=digest:
            raise ValueError('evidence hash changed')
        disposition=wintypes.BOOL(True)
        if not setinfo(handle,4,ctypes.byref(disposition),ctypes.sizeof(disposition)):
            raise OSError('handle deletion rejected')
        return True
    finally:
        for handle in reversed(handles):
            close(handle)
