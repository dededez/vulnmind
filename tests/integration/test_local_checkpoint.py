from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
pytest.importorskip("langgraph.checkpoint.sqlite")

from vulnmind.graph.local_checkpoint import local_checkpointer
from vulnmind.graph.workflow import build_graph


def test_planning_checkpoint_survives_process_restart(tmp_path):
    now = datetime.now(timezone.utc)
    state = {"task_id": "checkpoint-task", "project_id": "p", "targets": [{"type": "web", "locator": "https://example.test/api"}], "authorized_scope": {"authorization_source": "test", "approved_by": "owner", "starts_at": (now-timedelta(hours=1)).isoformat(), "expires_at": (now+timedelta(hours=1)).isoformat(), "web_origins": ["https://example.test"]}}
    db = tmp_path / "checkpoint.sqlite"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    script = """import json,sys\nfrom pathlib import Path\nfrom vulnmind.graph.local_checkpoint import local_checkpointer\nfrom vulnmind.graph.workflow import build_graph\nwith local_checkpointer(Path(sys.argv[1])) as saver:\n result=build_graph(saver).invoke(json.loads(Path(sys.argv[2]).read_text()), {'configurable':{'thread_id':'restart-test'}})\n assert result['status']=='planned'\n"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    child = subprocess.run([sys.executable, "-c", script, str(db), str(state_file)], capture_output=True, text=True, timeout=10, env=env)
    assert child.returncode == 0, child.stderr
    with local_checkpointer(db) as saver:
        graph = build_graph(saver)
        state_snapshot = graph.get_state({"configurable": {"thread_id": "restart-test"}})
        assert state_snapshot.values["task_id"] == "checkpoint-task"
        assert state_snapshot.values["status"] == "planned"
        assert state_snapshot.values["plan"]["target_types"] == ["web"]
