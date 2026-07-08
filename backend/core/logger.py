import sqlite3
import threading
import queue
import time
import json
import logging
import traceback
from datetime import datetime

# ── Configuration ──────────
LOGS_DB_PATH = '/mnt/extra_storage/IDS_Project/backend/logs.db'
MAX_QUEUE_SIZE = 50000
BATCH_SIZE = 500
BATCH_TIMEOUT = 1.0 # 1 second timeout for flushing batches
MAX_ROWS = 100000
RETENTION_DAYS = 30

# Memory Queue to avoid blocking the Event Loop
log_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
_worker_started = False
_stop_event = threading.Event()

# Dedicated logger for debugging the logger itself if needed
sys_logger = logging.getLogger("IDS_SystemLogger")
sys_logger.setLevel(logging.INFO)

def init_logs_db():
    """Initialize the SQLite database with WAL mode and table schema."""
    try:
        conn = sqlite3.connect(LOGS_DB_PATH, isolation_level=None)
        cursor = conn.cursor()
        
        # Maximize concurrency and speed
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                component TEXT NOT NULL,
                message TEXT NOT NULL,
                ip TEXT,
                stack_trace TEXT,
                raw_payload TEXT
            )
        ''')
        
        # Create indexes for fast filtering and pagination
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_level ON system_logs(level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_component ON system_logs(component)')
        
        conn.commit()
        conn.close()
    except Exception as e:
        sys_logger.error(f"Failed to initialize logs database: {e}")

def _db_worker():
    """Background worker that pulls logs from the queue and batch-inserts them to SQLite."""
    conn = sqlite3.connect(LOGS_DB_PATH, timeout=10.0)
    # Enable WAL in the worker connection as well
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    cursor = conn.cursor()
    
    batch = []
    last_cleanup = time.time()
    
    while not _stop_event.is_set():
        try:
            # Block for a short time to allow batch accumulation
            log_entry = log_queue.get(timeout=BATCH_TIMEOUT)
            batch.append(log_entry)
        except queue.Empty:
            pass # Timeout reached, proceed to flush batch if any
            
        # Flush if batch size reached or timeout hit with some data
        if len(batch) >= BATCH_SIZE or (batch and log_queue.empty()):
            try:
                cursor.executemany('''
                    INSERT INTO system_logs (timestamp, level, component, message, ip, stack_trace, raw_payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', batch)
                conn.commit()
                batch.clear()
            except Exception as e:
                sys_logger.error(f"Failed to insert log batch: {e}")
                # Optional: Handle failed batch (e.g., save to a fallback file or drop)
                batch.clear()
                
        # Periodic Cleanup (Every 10 minutes)
        if time.time() - last_cleanup > 600:
            _cleanup_logs(cursor)
            conn.commit()
            last_cleanup = time.time()
            
    conn.close()

def _cleanup_logs(cursor):
    """Enforce retention policy: Max 100,000 rows OR older than 30 days."""
    try:
        # Delete logs older than 30 days
        cursor.execute("DELETE FROM system_logs WHERE datetime(timestamp) <= datetime('now', '-30 days')")
        
        # Enforce FIFO size limit
        cursor.execute("SELECT COUNT(*) FROM system_logs")
        total_rows = cursor.fetchone()[0]
        
        if total_rows > MAX_ROWS:
            excess = total_rows - MAX_ROWS
            # Delete the oldest N rows
            cursor.execute(f"DELETE FROM system_logs WHERE id IN (SELECT id FROM system_logs ORDER BY id ASC LIMIT {excess})")
            
        # Optional: Vaccum to reclaim space if highly aggressive (disabled by default to avoid locking)
        # cursor.execute("VACUUM;") 
    except Exception as e:
        sys_logger.error(f"Cleanup failed: {e}")

def start_logger():
    """Initialize DB and start the background worker."""
    global _worker_started
    if _worker_started:
        return
        
    init_logs_db()
    t = threading.Thread(target=_db_worker, daemon=True, name="DBLoggerWorker")
    t.start()
    _worker_started = True

def log_event(level: str, component: str, message: str, ip: str = None, stack_trace: str = None, raw_payload: str = None):
    """Push a log entry to the high-performance memory queue."""
    if not _worker_started:
        start_logger()
        
    timestamp = datetime.now().isoformat(sep=' ', timespec='milliseconds')
    
    # Handle dict/json payloads safely
    if isinstance(raw_payload, dict):
        try:
            raw_payload = json.dumps(raw_payload)
        except:
            raw_payload = str(raw_payload)
            
    try:
        log_queue.put_nowait((
            timestamp,
            level.upper(),
            component,
            message,
            ip,
            stack_trace,
            raw_payload
        ))
    except queue.Full:
        sys_logger.warning("Log queue is full! Dropping log entry to prevent blocking.")

def get_logs(limit=50, offset=0, level=None, component=None, start_date=None, end_date=None):
    """Retrieve logs for the API."""
    try:
        conn = sqlite3.connect(LOGS_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM system_logs WHERE 1=1"
        params = []
        
        if level and level != "ALL":
            query += " AND level = ?"
            params.append(level.upper())
            
        if component and component != "ALL":
            query += " AND component = ?"
            params.append(component)
            
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
            
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
            
        # Count total matching before limit
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = [dict(row) for row in rows]
        conn.close()
        
        return {"total": total_count, "logs": logs}
    except Exception as e:
        sys_logger.error(f"Failed to fetch logs: {e}")
        return {"total": 0, "logs": []}
