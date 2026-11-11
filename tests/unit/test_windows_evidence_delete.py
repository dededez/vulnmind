import os
import time
import pytest
from vulnmind.evidence.store import EvidenceStore
from vulnmind.evidence.windows_delete import delete_verified

pytestmark=pytest.mark.skipif(os.name!='nt',reason='Windows handle deletion')


def test_hash_time_and_containment_rechecked_under_handle(tmp_path):
    store=EvidenceStore(tmp_path/'store')
    ref=store.put(b'owned orphan')
    path=store.root/ref.uri
    assert not delete_verified(store.root,ref.uri,ref.sha256,cutoff=time.time()-86400)
    assert path.exists()
    with pytest.raises(ValueError,match='hash changed'):
        delete_verified(store.root,ref.uri,'0'*64,cutoff=time.time()+1)
    assert path.exists()
    with pytest.raises(ValueError,match='invalid evidence path'):
        delete_verified(store.root,'../outside','0'*64,cutoff=time.time()+1)
    assert delete_verified(store.root,ref.uri,ref.sha256,cutoff=time.time()+1)
    assert not path.exists()
