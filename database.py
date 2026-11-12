import sqlite3

DB_NAME = "device_monitor.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        mac TEXT UNIQUE,
        vendor TEXT,
        last_seen TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS trusted_devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT UNIQUE,
        vendor TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blacklist_devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT UNIQUE,
        vendor TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        total INTEGER,
        known INTEGER,
        unknown INTEGER,
        high INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT,
        event_type TEXT,
        description TEXT
    )
    """)

    conn.commit()
    conn.close()

def normalize_mac(mac):
    return str(mac).replace("-", ":").upper().strip()

def add_log(event_type, description):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO activity_logs(event_time,event_type,description)
    VALUES(datetime('now','localtime'),?,?)
    """, (event_type, description))
    conn.commit()
    conn.close()

def get_logs(limit=50):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

def save_devices(devices):
    conn = get_connection()
    cur = conn.cursor()

    for d in devices:
        mac = normalize_mac(d.get("mac", "Unknown"))
        ip = d.get("ip", "Unknown")
        vendor = d.get("vendor", "Unknown")

        if mac in ["UNKNOWN", "", "NONE"]:
            continue

        cur.execute("""
        INSERT OR REPLACE INTO devices(ip,mac,vendor,last_seen)
        VALUES(?,?,?,datetime('now','localtime'))
        """, (ip, mac, vendor))

    conn.commit()
    conn.close()
    save_history()

def get_all_devices():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def get_device_by_mac(mac):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE UPPER(mac)=?", (normalize_mac(mac),))
    row = cur.fetchone()
    conn.close()
    return row

def add_trusted(mac, vendor="Unknown"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR IGNORE INTO trusted_devices(mac,vendor,created_at)
    VALUES(?,?,datetime('now','localtime'))
    """, (normalize_mac(mac), vendor))
    conn.commit()
    conn.close()
    add_log("TRUST", f"Đánh dấu tin cậy: {mac}")

def remove_trusted(mac):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM trusted_devices WHERE mac=?", (normalize_mac(mac),))
    conn.commit()
    conn.close()
    add_log("UNTRUST", f"Gỡ tin cậy: {mac}")

def get_trusted():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM trusted_devices ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def add_black(mac, vendor="Unknown"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR IGNORE INTO blacklist_devices(mac,vendor,created_at)
    VALUES(?,?,datetime('now','localtime'))
    """, (normalize_mac(mac), vendor))
    conn.commit()
    conn.close()
    add_log("BLOCK", f"Chặn thiết bị: {mac}")

def remove_black(mac):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM blacklist_devices WHERE mac=?", (normalize_mac(mac),))
    conn.commit()
    conn.close()
    add_log("UNBLOCK", f"Gỡ chặn thiết bị: {mac}")

def get_black():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM blacklist_devices ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def build_dashboard():
    devices = [dict(r) for r in get_all_devices()]
    trusted = set([normalize_mac(r["mac"]) for r in get_trusted()])
    blacklist = set([normalize_mac(r["mac"]) for r in get_black()])

    total = len(devices)
    known = 0
    unknown = 0
    high = 0

    for d in devices:
        mac = normalize_mac(d["mac"])
        vendor = d.get("vendor", "Unknown")

        if mac in blacklist:
            d["status"] = "Blocked"
        elif mac in trusted:
            d["status"] = "Known"
        else:
            d["status"] = "Unknown"

        score = 0
        if d["status"] == "Unknown":
            score += 50
        if vendor == "Unknown" or "Unknown" in vendor:
            score += 30
        if d["status"] == "Blocked":
            score += 100

        d["risk_score"] = score
        d["risk_level"] = "High" if score >= 80 else "Medium" if score >= 50 else "Low"

        if d["status"] == "Known":
            known += 1
        elif d["status"] == "Unknown":
            unknown += 1

        if d["risk_level"] == "High":
            high += 1

    return devices, trusted, blacklist, total, known, unknown, high

def save_history():
    devices, trusted, blacklist, total, known, unknown, high = build_dashboard()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO scan_history(scan_time,total,known,unknown,high)
    VALUES(datetime('now','localtime'),?,?,?,?)
    """, (total, known, unknown, high))
    conn.commit()
    conn.close()

def get_history():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scan_history ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows