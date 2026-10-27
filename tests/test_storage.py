import sqlite3

from hypothesis_pt.core import run_assessment
from hypothesis_pt.storage import RunStore


def test_store_persists_and_verifies(tmp_path):
    dbfile = str(tmp_path / "evidence.db")
    store = RunStore(dbfile)
    first = run_assessment("vulnerable")
    second = run_assessment("secure")
    store.save(first)
    store.save(second)
    assert store.get(first["id"])["summary"]["potential_findings"] == 2
    assert store.verify(first["id"])["verified"]
    assert store.verify(second["id"])["verified"]
    assert len(store.list_runs()) == 2


def test_tampering_breaks_chain(tmp_path):
    path = str(tmp_path / "evidence.db")
    store = RunStore(path)
    result = run_assessment("secure")
    store.save(result)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE runs SET scenario = 'vulnerable', payload = '{}' WHERE id=?", (result["id"],))
    assert not store.verify(result["id"])["verified"]
