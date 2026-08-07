import sqlite3
import json
import time
import os
import functools
from pathlib import Path

import malwoverview.modules.configvars as cv


def default_db_path():
    return os.path.join(str(Path.home()), '.malwoverview_cache.db')


class ResultCache:
    def __init__(self, db_path=None, default_ttl=3600):
        if db_path is None:
            db_path = default_db_path()
        self.db_path = db_path
        self.default_ttl = default_ttl
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute(
            'CREATE TABLE IF NOT EXISTS cache '
            '(key TEXT PRIMARY KEY, value TEXT, timestamp REAL)'
        )
        self.conn.commit()

    def get(self, key):
        cursor = self.conn.execute(
            'SELECT value, timestamp FROM cache WHERE key=?', (key,)
        )
        row = cursor.fetchone()
        cursor.close()
        if row is not None:
            value, timestamp = row
            if time.time() - timestamp < self.default_ttl:
                return json.loads(value)
        return None

    def put(self, key, value, ttl=None):
        self.conn.execute(
            'INSERT OR REPLACE INTO cache (key, value, timestamp) VALUES (?, ?, ?)',
            (key, json.dumps(value), time.time())
        )
        self.conn.commit()

    def clear(self):
        cursor = self.conn.execute('DELETE FROM cache')
        self.conn.commit()
        return max(cursor.rowcount, 0)

    def prune(self, ttl=None):
        if ttl is None:
            ttl = self.default_ttl
        cursor = self.conn.execute(
            'DELETE FROM cache WHERE timestamp < ?',
            (time.time() - ttl,)
        )
        self.conn.commit()
        return max(cursor.rowcount, 0)

    def stats(self, ttl=None):
        if ttl is None:
            ttl = self.default_ttl
        entries = self.conn.execute('SELECT COUNT(*) FROM cache').fetchone()[0]
        expired = self.conn.execute(
            'SELECT COUNT(*) FROM cache WHERE timestamp < ?',
            (time.time() - ttl,)
        ).fetchone()[0]
        try:
            size_bytes = os.path.getsize(self.db_path)
        except OSError:
            size_bytes = 0
        return {
            'db_path': self.db_path,
            'entries': entries,
            'expired': expired,
            'ttl': ttl,
            'size_bytes': size_bytes
        }

    def close(self):
        self.conn.close()


def cached(key_prefix):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not cv.cache_enabled:
                return func(*args, **kwargs)
            cache = ResultCache(default_ttl=cv.cache_ttl)
            try:
                cache_key = key_prefix + ":" + ":".join(str(a) for a in args[1:])
                result = cache.get(cache_key)
                if result is not None:
                    return result
                result = func(*args, **kwargs)
                if result is not None:
                    cache.put(cache_key, result)
                return result
            finally:
                cache.close()
        return wrapper
    return decorator


def clear_cache(db_path=None):
    path = db_path if db_path is not None else default_db_path()
    if not os.path.exists(path):
        return 0
    cache = ResultCache(db_path=path, default_ttl=cv.cache_ttl)
    try:
        return cache.clear()
    finally:
        cache.close()


def prune_cache(db_path=None, ttl=None):
    path = db_path if db_path is not None else default_db_path()
    if not os.path.exists(path):
        return 0
    if ttl is None:
        ttl = cv.cache_ttl
    cache = ResultCache(db_path=path, default_ttl=ttl)
    try:
        return cache.prune()
    finally:
        cache.close()


def cache_stats(db_path=None, ttl=None):
    path = db_path if db_path is not None else default_db_path()
    if ttl is None:
        ttl = cv.cache_ttl
    if not os.path.exists(path):
        return {
            'db_path': path,
            'entries': 0,
            'expired': 0,
            'ttl': ttl,
            'size_bytes': 0
        }
    cache = ResultCache(db_path=path, default_ttl=ttl)
    try:
        return cache.stats()
    finally:
        cache.close()
