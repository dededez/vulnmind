"""Windows-user encrypted origin-bound credentials. Never stored in job JSON."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
from uuid import uuid4


class Vault:
    def __init__(self,root):
        self.root=Path(root); self.root.mkdir(parents=True,exist_ok=True)

    def _crypt(self,data,encrypt):
        if os.name!='nt': raise ValueError('credential profiles require Windows DPAPI in this local release')
        class Blob(ctypes.Structure):
            _fields_=[('length',wintypes.DWORD),('data',ctypes.POINTER(ctypes.c_byte))]
        buffer=ctypes.create_string_buffer(data)
        source=Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_byte))); output=Blob()
        crypt=ctypes.WinDLL('crypt32',use_last_error=True)
        function=crypt.CryptProtectData if encrypt else crypt.CryptUnprotectData
        if not function(ctypes.byref(source),None,None,None,None,1,ctypes.byref(output)):
            raise OSError('credential encryption unavailable')
        try: return ctypes.string_at(output.data,output.length)
        finally:
            kernel=ctypes.WinDLL('kernel32'); kernel.LocalFree.argtypes=[ctypes.c_void_p]
            kernel.LocalFree(output.data)

    def save(self,origin,kind,value):
        from vulnmind.analysis.http_broker_worker import origin as parse
        parse(origin)
        if kind not in {'bearer','cookie'} or not value or len(value)>8000 or any(ord(c)<32 for c in value):
            raise ValueError('invalid credential')
        identifier=uuid4().hex
        encoded=self._crypt(json.dumps(dict(origin=origin,kind=kind,value=value)).encode(),True)
        with (self.root/(identifier+'.bin')).open('xb') as stream: stream.write(encoded)
        return identifier

    def load(self,identifier,origin):
        from uuid import UUID
        identifier=UUID(identifier).hex
        path=self.root/(identifier+'.bin')
        if path.is_symlink() or path.stat().st_size>20000: raise ValueError('invalid credential profile')
        value=json.loads(self._crypt(path.read_bytes(),False))
        if value['origin']!=origin: raise ValueError('credential origin mismatch')
        return {'Authorization':'Bearer '+value['value']} if value['kind']=='bearer' else {'Cookie':value['value']}

    def save_account(self,origin,email,password):
        """Persist one test account (email/password) for authorized registration flows."""
        from vulnmind.analysis.http_broker_worker import origin as parse
        parse(origin)
        if not email or len(email)>200 or '@' not in email: raise ValueError('invalid account email')
        if not password or len(password)<12 or len(password)>200: raise ValueError('invalid account password')
        identifier=uuid4().hex
        encoded=self._crypt(json.dumps(dict(origin=origin,kind='account',email=email,password=password)).encode(),True)
        with (self.root/('account-'+identifier+'.bin')).open('xb') as stream: stream.write(encoded)
        return identifier

    def load_account(self,identifier,origin):
        from uuid import UUID
        identifier=UUID(identifier).hex
        path=self.root/('account-'+identifier+'.bin')
        if not path.is_file() or path.is_symlink() or path.stat().st_size>20000:
            raise ValueError('invalid account profile')
        value=json.loads(self._crypt(path.read_bytes(),False))
        if value.get('kind')!='account' or value.get('origin')!=origin:
            raise ValueError('account origin mismatch')
        return dict(email=value['email'],password=value['password'])

    def save_session(self,workflow,origin,token,bid=None):
        """Persist one short-lived session token encrypted, bound to origin and workflow."""
        from vulnmind.analysis.http_broker_worker import origin as parse
        from uuid import UUID
        parse(origin)
        if not token or len(token)>8000: raise ValueError('invalid session token')
        if bid is not None and (not isinstance(bid,int) or isinstance(bid,bool)): raise ValueError('invalid basket id')
        path=self.root/('session-'+UUID(str(workflow)).hex+'.bin')
        encoded=self._crypt(json.dumps(dict(origin=origin,kind='session',token=token,bid=bid)).encode(),True)
        path.write_bytes(encoded)

    def load_session(self,workflow,origin):
        from uuid import UUID
        path=self.root/('session-'+UUID(str(workflow)).hex+'.bin')
        if not path.is_file() or path.is_symlink() or path.stat().st_size>20000: return None
        value=json.loads(self._crypt(path.read_bytes(),False))
        if value.get('kind')!='session' or value.get('origin')!=origin: return None
        return dict(token=value.get('token'),bid=value.get('bid'))
