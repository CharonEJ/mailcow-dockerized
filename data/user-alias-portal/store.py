"""SQLite storage for per-user synonym configuration.

Only the synonym lives here; the aliases themselves are stored in
mailcow (single source of truth) and always fetched via its API.
"""

import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_alias_config (
  username    TEXT PRIMARY KEY,
  synonym     TEXT,
  domain      TEXT NOT NULL,
  synonym_set INTEGER NOT NULL DEFAULT 0,
  created     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS synonym_domain_unique
  ON user_alias_config (synonym, domain);
"""


class Store:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def get_config(self, username):
        with self._lock:
            row = self._conn.execute(
                "SELECT username, synonym, domain, synonym_set, created"
                " FROM user_alias_config WHERE username = ?",
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def get_synonym(self, username):
        cfg = self.get_config(username)
        if cfg and cfg["synonym_set"] and cfg["synonym"]:
            return cfg["synonym"]
        return None

    def claim_synonym(self, username, synonym, domain):
        """Atomically reserve the synonym. Returns False if the user has
        already set one or the synonym is taken in this domain."""
        with self._lock:
            try:
                cur = self._conn.execute(
                    "INSERT INTO user_alias_config"
                    " (username, synonym, domain, synonym_set)"
                    " VALUES (?, ?, ?, 1)"
                    " ON CONFLICT(username) DO UPDATE SET"
                    "   synonym = excluded.synonym,"
                    "   domain = excluded.domain,"
                    "   synonym_set = 1"
                    " WHERE user_alias_config.synonym_set = 0",
                    (username, synonym, domain),
                )
                self._conn.commit()
                return cur.rowcount > 0
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def release_synonym(self, username):
        """Rollback helper: only used when creating the forwarding alias
        in mailcow failed right after claiming."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM user_alias_config WHERE username = ?",
                (username,),
            )
            self._conn.commit()
