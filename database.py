import sqlite3
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.db")


def get_connection(db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_file=DB_FILE):
    """Create tables if they don't already exist."""
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            resolved_ip TEXT,
            hostname TEXT,
            start_time TEXT,
            end_time TEXT,
            port_range TEXT,
            total_open INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            risk_level TEXT,
            risk_note TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)
    conn.commit()
    conn.close()


def create_scan(target, resolved_ip, hostname, port_range, db_file=DB_FILE):
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scans (target, resolved_ip, hostname, start_time, port_range)
        VALUES (?, ?, ?, ?, ?)
    """, (target, resolved_ip, hostname, datetime.now().isoformat(), port_range))
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def finish_scan(scan_id, total_open, db_file=DB_FILE):
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("""
        UPDATE scans SET end_time = ?, total_open = ? WHERE id = ?
    """, (datetime.now().isoformat(), total_open, scan_id))
    conn.commit()
    conn.close()


def add_result(scan_id, port, state, service, risk_level, risk_note, db_file=DB_FILE):
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO results (scan_id, port, state, service, risk_level, risk_note)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, port, state, service, risk_level, risk_note))
    conn.commit()
    conn.close()


def get_scans(db_file=DB_FILE):
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_results(scan_id, db_file=DB_FILE):
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT * FROM results WHERE scan_id = ? ORDER BY port ASC", (scan_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_scan(scan_id, db_file=DB_FILE):
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("DELETE FROM results WHERE scan_id = ?", (scan_id,))
    cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()