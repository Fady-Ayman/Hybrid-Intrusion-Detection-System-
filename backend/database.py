"""
database.py
===========
SQLite persistence layer for alerts.

CRITICAL: This file is the bridge between the aggregator (which produces
aggregated rows with snake_case fields + a list of ports) and the existing
schema (which uses camelCase + flat columns). The integration handles:

  1. JSON-serialization of `targeted_ports` (SQLite can't store lists).
  2. Field-name mapping: src_ip -> srcIp, dst_ip -> dstIp, etc.
  3. Deterministic `id` generation for aggregated rows (so INSERT OR IGNORE
     can deduplicate without dropping legitimate rows).
  4. Migration to add the new aggregator columns (idempotent ALTER TABLE).
  5. Derivation of severity / signature / category / action / is_attack
     from the aggregator payload.
  6. Backward compatibility: legacy single-alert inserts still work.
"""
import sqlite3
import os
import json
import hashlib
import threading
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts.db")
db_lock = threading.Lock()


def get_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
def init_db():
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                db_id INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT UNIQUE,
                timestamp TEXT,
                severity TEXT,
                signature TEXT,
                signatureId INTEGER,
                category TEXT,
                srcIp TEXT,
                srcPort INTEGER,
                dstIp TEXT,
                dstPort INTEGER,
                protocol TEXT,
                action TEXT,
                is_attack BOOLEAN,
                confidence REAL,
                label TEXT,
                raw_label TEXT
            )
        ''')
        
        # ---- NEW: users table for Authentication & RBAC ----
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        
        # INTENTIONAL VULNERABILITY (CWE-256): Store passwords in plain-text
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
            cursor.execute("INSERT INTO users (username, password, role) VALUES ('user', 'user123', 'user')")
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts (timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts (severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_srcIp ON alerts (srcIp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dstIp ON alerts (dstIp)')

        # ---- Existing migrations (legacy) ----
        cursor.execute("PRAGMA table_info(alerts);")
        columns = [col[1] for col in cursor.fetchall()]

        if "detection_source" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN detection_source TEXT DEFAULT 'ML';")
            columns.append("detection_source")
        if "is_pcap" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN is_pcap INTEGER DEFAULT 0;")
            columns.append("is_pcap")

        # ---- NEW migrations for the aggregator ----
        # hit_count: how many raw alerts were merged into this row
        if "hit_count" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN hit_count INTEGER DEFAULT 1;")
            columns.append("hit_count")
        # port_count: number of distinct ports targeted (port-scan forensics)
        if "port_count" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN port_count INTEGER DEFAULT 0;")
            columns.append("port_count")
        # duration: seconds between first and last hit
        if "duration" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN duration REAL DEFAULT 0.0;")
            columns.append("duration")
        # family: aggregator family (scan / brute / flood / generic)
        if "family" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN family TEXT;")
            columns.append("family")
        # targeted_ports: JSON-serialised list of ports (e.g. "[80, 443, 22]")
        if "targeted_ports" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN targeted_ports TEXT;")
            columns.append("targeted_ports")
        # first_seen: ISO timestamp of the first hit in the aggregation window
        if "first_seen" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN first_seen TEXT;")
            columns.append("first_seen")
        # last_seen: ISO timestamp of the last hit (alias of timestamp for aggregated rows)
        if "last_seen" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN last_seen TEXT;")
            columns.append("last_seen")

        # Index for filtering aggregated-only rows quickly
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_hit_count ON alerts (hit_count);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_family ON alerts (family);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_pcap ON alerts(is_pcap);')

        conn.commit()
        conn.close()
        print(f"[Database] SQLite DB initialized at {DB_PATH}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _epoch_to_iso(epoch: float) -> str:
    """Convert a unix epoch float to an ISO-8601 string (UTC)."""
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _serialize_ports(ports) -> str:
    """JSON-serialise a list/set of ports for SQLite storage."""
    if ports is None:
        return "[]"
    if isinstance(ports, set):
        ports = sorted(ports)
    try:
        return json.dumps(list(ports))
    except (TypeError, ValueError):
        return "[]"


def _derive_severity(hit_count: int, attack_type: str = "") -> str:
    """Map hit_count + attack_type to a severity tier."""
    if attack_type and "flood" in attack_type.lower():
        return "CRITICAL" if hit_count >= 100 else "HIGH"
    if hit_count >= 100:
        return "CRITICAL"
    if hit_count >= 50:
        return "HIGH"
    if hit_count >= 10:
        return "MEDIUM"
    return "LOW"


def _gen_aggregated_id(entry: dict) -> str:
    """
    Deterministic id for an aggregated row.
    Same (src, dst, attack_type, window_start) -> same id -> INSERT OR IGNORE dedupes safely.
    """
    base = "|".join([
        str(entry.get("src_ip", "")),
        str(entry.get("dst_ip", "")),
        str(entry.get("attack_type", "")),
        str(int(float(entry.get("first_seen", 0) or 0))),
        str(entry.get("is_pcap", 0)),
    ])
    return "agg-" + hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]


def _is_aggregated(alert: dict) -> bool:
    """Detect whether this dict came from the aggregator or a legacy single-alert caller."""
    return "hit_count" in alert or "family" in alert or "targeted_ports" in alert


# ---------------------------------------------------------------------------
# insert_alert — routes to single or aggregated path
# ---------------------------------------------------------------------------
def insert_alert(alert: dict):
    """
    Insert one alert. Auto-detects whether the payload came from the
    aggregator (hit_count / family present) or from legacy Snort/ML code.

    Aggregated payloads get:
      - field-name mapping (src_ip -> srcIp, etc.)
      - JSON-serialised targeted_ports
      - derived severity / signature / category / action
      - generated unique id
    """
    if _is_aggregated(alert):
        _insert_aggregated_alert(alert)
    else:
        _insert_single_alert(alert)


def _insert_single_alert(alert: dict):
    """Legacy path — original logic, unchanged."""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO alerts (
                    id, timestamp, severity, signature, signatureId, category,
                    srcIp, srcPort, dstIp, dstPort, protocol, action,
                    is_attack, confidence, label, raw_label, detection_source, is_pcap
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.get("id"),
                alert.get("timestamp"),
                alert.get("severity"),
                alert.get("signature"),
                alert.get("signatureId"),
                alert.get("category"),
                alert.get("srcIp"),
                alert.get("srcPort"),
                alert.get("dstIp"),
                alert.get("dstPort"),
                alert.get("protocol"),
                alert.get("action"),
                alert.get("is_attack"),
                alert.get("confidence"),
                alert.get("label"),
                alert.get("raw_label"),
                alert.get("detection_source", "ML"),
                alert.get("is_pcap", 0)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Database Error] insert_alert: {e}")


def _insert_aggregated_alert(alert: dict):
    """
    New path — handles payloads produced by core/aggregator.py.

    Field mapping (aggregator -> DB column):
        src_ip          -> srcIp
        src_port        -> srcPort
        dst_ip          -> dstIp
        dst_port        -> dstPort           (first port seen)
        proto           -> protocol
        attack_type     -> label             (the ML classification)
        classification  -> signature         (the rule message)
        confidence      -> confidence
        is_pcap         -> is_pcap
        hit_count       -> hit_count
        port_count      -> port_count
        duration        -> duration
        family          -> family
        targeted_ports  -> targeted_ports    (JSON-serialised)
        first_seen      -> first_seen        (epoch -> ISO)
        last_seen       -> last_seen + timestamp (epoch -> ISO)

    Derived fields:
        id              -> deterministic hash
        severity        -> from hit_count + attack_type
        category        -> family
        action          -> 'aggregated'
        is_attack       -> 1 (aggregator only forwards attacks)
        detection_source -> 'ML_AGGREGATED'
    """
    with db_lock:
        try:
            # ---- map field names ----
            src_ip          = alert.get("src_ip") or alert.get("srcIp")
            src_port        = alert.get("src_port") or alert.get("srcPort")
            dst_ip          = alert.get("dst_ip") or alert.get("dstIp")
            dst_port        = alert.get("dst_port") or alert.get("dstPort")
            proto           = alert.get("proto") or alert.get("protocol")
            attack_type     = alert.get("attack_type") or alert.get("label", "")
            classification  = alert.get("classification") or alert.get("signature", "")
            confidence      = float(alert.get("confidence", 0.0) or 0.0)
            is_pcap         = int(alert.get("is_pcap", 0) or 0)
            hit_count       = int(alert.get("hit_count", 1) or 1)
            port_count      = int(alert.get("port_count", 0) or 0)
            duration        = float(alert.get("duration", 0.0) or 0.0)
            family          = alert.get("family", "generic")
            targeted_ports  = alert.get("targeted_ports")
            first_seen      = alert.get("first_seen")
            last_seen       = alert.get("last_seen")

            # ---- derived fields ----
            alert_id        = alert.get("id") or _gen_aggregated_id(alert)
            severity        = _derive_severity(hit_count, attack_type)
            category        = family
            action          = "aggregated"
            is_attack       = 1
            detection_source = "ML_AGGREGATED"

            # ---- format conversions ----
            first_seen_iso  = _epoch_to_iso(first_seen) if first_seen else None
            last_seen_iso   = _epoch_to_iso(last_seen)  if last_seen  else None
            # `timestamp` column gets the last_seen (so existing UI sorts by recency)
            timestamp       = last_seen_iso or first_seen_iso or datetime.now(timezone.utc).isoformat()
            targeted_ports_json = _serialize_ports(targeted_ports)

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO alerts (
                    id, timestamp, severity, signature, signatureId, category,
                    srcIp, srcPort, dstIp, dstPort, protocol, action,
                    is_attack, confidence, label, raw_label,
                    detection_source, is_pcap,
                    hit_count, port_count, duration, family,
                    targeted_ports, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_id,
                timestamp,
                severity,
                classification,           # signature
                None,                     # signatureId
                category,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                proto,
                action,
                is_attack,
                confidence,
                attack_type,              # label
                None,                     # raw_label
                detection_source,
                is_pcap,
                hit_count,
                port_count,
                duration,
                family,
                targeted_ports_json,
                first_seen_iso,
                last_seen_iso,
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Database Error] _insert_aggregated_alert: {e}")


# ---------------------------------------------------------------------------
# Batch insert (legacy + aggregated mixed)
# ---------------------------------------------------------------------------
def insert_alerts_batch(alerts: list):
    if not alerts:
        return
    # Split: aggregated rows go through the new path, legacy rows through the old one
    aggregated = [a for a in alerts if _is_aggregated(a)]
    legacy     = [a for a in alerts if not _is_aggregated(a)]

    if legacy:
        _insert_legacy_batch(legacy)
    if aggregated:
        for a in aggregated:
            _insert_aggregated_alert(a)


def _insert_legacy_batch(alerts: list):
    with db_lock:
        try:
            conn = get_connection()
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')
            cursor = conn.cursor()

            batch_data = []
            for alert in alerts:
                batch_data.append((
                    alert.get("id"), alert.get("timestamp"), alert.get("severity"),
                    alert.get("signature"), alert.get("signatureId"), alert.get("category"),
                    alert.get("srcIp"), alert.get("srcPort"), alert.get("dstIp"), alert.get("dstPort"),
                    alert.get("protocol"), alert.get("action"), alert.get("is_attack"),
                    alert.get("confidence"), alert.get("label"), alert.get("raw_label"),
                    alert.get("detection_source", "ML"), alert.get("is_pcap", 0)
                ))

            cursor.executemany('''
                INSERT OR IGNORE INTO alerts (
                    id, timestamp, severity, signature, signatureId, category,
                    srcIp, srcPort, dstIp, dstPort, protocol, action,
                    is_attack, confidence, label, raw_label, detection_source, is_pcap
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', batch_data)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Database Error] insert_alerts_batch: {e}")
            raise e


# ---------------------------------------------------------------------------
# Authentication & RBAC
# ---------------------------------------------------------------------------

def verify_user(username, password):
    """
    Verifies user credentials.
    INTENTIONAL VULNERABILITY: Compares plain-text passwords directly.
    Returns user dict (id, username, role) if valid, otherwise None.
    """
    with db_lock:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user['password'] == password:
            return {"id": user['id'], "username": user['username'], "role": user['role']}
        return None

def get_user_by_id(user_id):
    """
    Retrieves user dict by ID.
    """
    with db_lock:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {"id": user['id'], "username": user['username'], "role": user['role']}
        return None


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------
def get_alerts(page=1, limit=50, severity="ALL", search="", sort_order="desc", origin="ALL"):
    with db_lock:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if origin == "LIVE":
            query += " AND is_pcap = ?"
            params.append(0)
        elif origin == "PCAP":
            query += " AND is_pcap = ?"
            params.append(1)

        if severity and severity != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())

        if search:
            search_term = f"%{search}%"
            query += " AND (signature LIKE ? OR srcIp LIKE ? OR dstIp LIKE ? OR label LIKE ?)"
            params.extend([search_term, search_term, search_term, search_term])

        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        if sort_order.lower() == "asc":
            query += " ORDER BY timestamp ASC"
        else:
            query += " ORDER BY timestamp DESC"

        offset = (page - 1) * limit
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        alerts_list = []
        for row in rows:
            a = dict(row)
            # boolean conversion
            if a.get('is_attack') is not None:
                a['is_attack'] = bool(a['is_attack'])
            # deserialize targeted_ports JSON back to a list for the UI
            if a.get('targeted_ports'):
                try:
                    a['targeted_ports'] = json.loads(a['targeted_ports'])
                except (json.JSONDecodeError, TypeError):
                    a['targeted_ports'] = []
            else:
                a['targeted_ports'] = []
            alerts_list.append(a)

        conn.close()

        return {
            "total": total,
            "page": page,
            "limit": limit,
            "totalPages": (total + limit - 1) // limit,
            "alerts": alerts_list
        }


# ---------------------------------------------------------------------------
# Optional helper — aggregator stats endpoint
# ---------------------------------------------------------------------------
def get_aggregator_stats() -> dict:
    """Quick aggregates-only stats. Useful for a /stats endpoint."""
    with db_lock:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute('''
                SELECT
                    COUNT(*)                                    AS aggregated_rows,
                    COALESCE(SUM(hit_count), 0)                 AS total_hits,
                    COALESCE(SUM(port_count), 0)                AS total_ports,
                    COALESCE(MAX(hit_count), 0)                 AS max_hits,
                    COALESCE(AVG(hit_count), 0)                 AS avg_hits
                FROM alerts
                WHERE hit_count > 1
            ''')
            row = dict(cursor.fetchone() or {})
        except sqlite3.OperationalError:
            row = {}
        conn.close()
        return row
