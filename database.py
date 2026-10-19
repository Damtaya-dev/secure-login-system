import os
import sqlite3
from pathlib import Path
from flask import g

DB_PATH = Path(os.environ.get('APP_DB_PATH', Path(__file__).with_name('users.db')))
ROLES = ('inputer', 'manager', 'admin', 'administrator')

def connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys = ON')
    return con

def get_db():
    if 'db' not in g:
        g.db = connect()
    return g.db

def close_db(_error=None):
    db = g.pop('db', None)
    if db is not None: db.close()

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('inputer','manager','admin','administrator')),
            totp_secret TEXT,
            totp_last_step INTEGER NOT NULL DEFAULT -1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );''')
