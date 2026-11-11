"""The built-in analyzer treats source as data; it never executes a file."""
from hashlib import sha256

from vulnmind.analysis.python_tls import find_python_tls_candidates
from vulnmind.tools.repo_files import FileContent


def test_source_with_side_effect_is_not_executed(tmp_path):
    marker = tmp_path / "would_be_created"
    text = f"from pathlib import Path\nPath({str(marker)!r}).touch()\nrequests.get(\"/\", verify=False)\n"
    item = FileContent(path="sample.py", language="python", encoding="utf-8",
                       size_bytes=len(text.encode()), sha256=sha256(text.encode()).hexdigest(), content=text)
    result = find_python_tls_candidates(item)
    assert not marker.exists()
    assert len(result) == 1 and result[0].status == "unverified"
