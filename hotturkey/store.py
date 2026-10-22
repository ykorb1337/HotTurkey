import json
import os
import sqlite3
import threading
from pathlib import Path
from .model import DEFAULT_SETTINGS

class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.directory / "hotturkey.sqlite3"), check_same_thread=False)
        os.chmod(self.directory / "hotturkey.sqlite3", 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
          PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at REAL, user TEXT, kind TEXT, target TEXT, block_id TEXT, seconds REAL, blocked INTEGER);
          CREATE INDEX IF NOT EXISTS event_time ON events(at);
          CREATE TABLE IF NOT EXISTS event_blocks (event_id INTEGER, block_id TEXT, PRIMARY KEY(event_id,block_id));
          CREATE INDEX IF NOT EXISTS event_block_lookup ON event_blocks(block_id,event_id);
          CREATE TABLE IF NOT EXISTS charges (at REAL, block_id TEXT, seconds REAL);
          CREATE INDEX IF NOT EXISTS charge_lookup ON charges(block_id,at);
        ''')
        row = self.db.execute("SELECT value FROM state WHERE id=1").fetchone()
        self.state = json.loads(row[0]) if row else {"version":1,"blocks":[],"runtime":{},"settings":dict(DEFAULT_SETTINGS),"last_time":0}
        self.state["settings"] = {**DEFAULT_SETTINGS, **self.state.get("settings",{})}
        if not row:self.save()

    def save(self):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO state VALUES (1,?)", (json.dumps(self.state,ensure_ascii=False),))
            self.db.commit()

    def event(self, at, user, kind, target, block_id="", seconds=0, blocked=False, block_ids=None):
        with self.lock:
            cursor=self.db.execute("INSERT INTO events(at,user,kind,target,block_id,seconds,blocked) VALUES(?,?,?,?,?,?,?)", (at,user,kind,target,block_id,seconds,int(blocked)))
            ids=set(block_ids or ([block_id] if block_id else []))
            self.db.executemany("INSERT OR IGNORE INTO event_blocks VALUES(?,?)",[(cursor.lastrowid,ident) for ident in ids])
            self.db.commit()

    def charge(self, at, block_id, seconds):
        with self.lock:
            self.db.execute("INSERT INTO charges VALUES(?,?,?)", (at,block_id,seconds))
            self.db.commit()

    def used(self, block_id, since):
        with self.lock:
            return self.db.execute("SELECT COALESCE(SUM(seconds),0) FROM charges WHERE block_id=? AND at>=?", (block_id,since)).fetchone()[0]

    def statistics(self, since=0, until=1e20, user="", query="", block="", kind=""):
        sql, args = "at>=? AND at<=?", [since,until]
        for field, value in (("user",user),("kind",kind)):
            if value:
                sql += f" AND {field}=?"
                args.append(value)
        if block:
            sql += " AND (events.block_id=? OR EXISTS(SELECT 1 FROM event_blocks eb WHERE eb.event_id=events.id AND eb.block_id=?))"
            args.extend([block,block])
        if query:
            sql += " AND instr(lower(target),lower(?))>0"
            args.append(query)
        with self.lock:
            rows = self.db.execute(f"SELECT target,kind,SUM(seconds) seconds,SUM(blocked) blocked FROM events WHERE {sql} GROUP BY target,kind ORDER BY seconds DESC,blocked DESC LIMIT 100",args).fetchall()
            days = self.db.execute(f"SELECT date(at,'unixepoch','localtime') day,SUM(seconds) seconds,SUM(blocked) blocked FROM events WHERE {sql} GROUP BY day ORDER BY day",args).fetchall()
            totals = self.db.execute(f"SELECT COALESCE(SUM(seconds),0) seconds,COALESCE(SUM(blocked),0) blocked,COUNT(DISTINCT kind||':'||target) targets FROM events WHERE {sql}",args).fetchone()
        return {"items":[dict(r) for r in rows],"days":[dict(r) for r in days],"totals":dict(totals)}

    def export_statistics(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM events ORDER BY at")]

    def clear_statistics(self):
        # Usage charges are independent; deleting statistics cannot refill an allowance.
        with self.lock:
            self.db.execute("DELETE FROM events")
            self.db.execute("DELETE FROM event_blocks")
            self.db.commit()

    def prune(self, now):
        with self.lock:
            self.db.execute("DELETE FROM events WHERE at<?",(now-self.state["settings"]["retention_days"]*86400,))
            self.db.execute("DELETE FROM event_blocks WHERE event_id NOT IN (SELECT id FROM events)")
            self.db.execute("DELETE FROM charges WHERE at<?",(now-62*86400,))
            self.db.commit()
