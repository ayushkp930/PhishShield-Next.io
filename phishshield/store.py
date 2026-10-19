import json, os, sqlite3
from pathlib import Path

def db_path(): return os.getenv("PHISHSHIELD_DB_PATH", "./data/phishshield.sqlite3")
def connect():
    p=Path(db_path()); p.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(p); c.row_factory=sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, input TEXT NOT NULL, verdict TEXT NOT NULL, risk_score INTEGER NOT NULL, result_json TEXT NOT NULL)")
    c.commit(); return c
def save(result):
    with connect() as c:
        c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?)",(result['id'],result['created_at'],result['input'],result['verdict'],result['risk_score'],json.dumps(result)))
def recent(limit=25):
    with connect() as c:
        rows=c.execute("SELECT id,created_at,input,verdict,risk_score FROM scans ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall()
        return [dict(r) for r in rows]
def get_scan(scan_id):
    with connect() as c:
        row=c.execute("SELECT result_json FROM scans WHERE id=?",(scan_id,)).fetchone()
        return json.loads(row[0]) if row else None
