import os
import socket
import numpy as np
import pandas as pd
import joblib

# Disable CUDA to prevent cuInit warnings
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import tensorflow as tf
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, BackgroundTasks, Query, Depends, Response, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import threading
import queue
import json
import uuid
import time
import psutil
from datetime import datetime, timedelta, timezone
import auth
import shutil
from collections import deque
from contextlib import asynccontextmanager
import logging

# ── Graceful Shutdown Event ───────────────────────────────
stop_event = threading.Event()
from core.filters import suppress_false_positive

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("IDS_Backend")

class SystemLoggerHandler(logging.Handler):
    def emit(self, record):
        if record.name == "IDS_SystemLogger":
            return
        
        try:
            level = record.levelname
            message = self.format(record)
            component = "Backend"
            if "[Snort]" in message: component = "Snort"
            elif "[Socket]" in message: component = "Socket"
            elif "[DB]" in message: component = "Database"
            elif "[Startup]" in message or "[Shutdown]" in message: component = "Lifecycle"
            elif "Worker" in message: component = "Worker"
            
            # Avoid circular import or undefined function issues by using system_logger directly
            system_logger.log_event(level, component, message)
            
            # Broadcast CRITICAL/ERROR to WebSocket
            if level in ["ERROR", "CRITICAL"]:
                log_entry = {
                    "timestamp": datetime.now().isoformat(sep=' ', timespec='milliseconds'),
                    "level": level,
                    "component": component,
                    "message": message,
                    "ip": None,
                    "stack_trace": None,
                    "raw_payload": None
                }
                if 'main_loop' in globals() and main_loop and main_loop.is_running():
                    asyncio.run_coroutine_threadsafe(broadcast_system_log(log_entry), main_loop)
        except Exception:
            pass

logger.addHandler(SystemLoggerHandler())

model_lock = threading.Lock()

from tracker import NetworkTracker
from core.pcap_analyzer import extract_flows_from_pcap
from core.snort_controller import SnortController
from core.aggregator import init_aggregator, ingest_alert, shutdown_aggregator, get_metrics
import database
import core.logger as system_logger

# ── Paths ─────────────────────────────────────────────────
BASE        = '/mnt/extra_storage/IDS_Project/model'
MODEL_PATH  = os.path.join(BASE, 'best_model_v2.keras')
SCALER_PATH = os.path.join(BASE, 'scaler.pkl')
LE_PATH     = os.path.join(BASE, 'label_encoder.pkl')
FEAT_PATH   = os.path.join(BASE, 'feature_names.csv')

# ── Load model & preprocessors ────────────────────────────
print("Loading model...")
model    = tf.keras.models.load_model(MODEL_PATH)
scaler   = joblib.load(SCALER_PATH)
le       = joblib.load(LE_PATH)

# الصف الأول في الملف هو "0" (header زائد) - نتجاهله
all_rows = pd.read_csv(FEAT_PATH, header=None)[0].tolist()
features = all_rows[1:]  # الـ 65 feature الحقيقيين بالترتيب
N        = len(features)

print(f"Ready! Features={N}, Classes={list(le.classes_)}")
print(f"Input shape expected: {model.input_shape}")

# ── Indices للـ features المعرضة لـ inf ───────────────────
IDX_FLOW_BYTES_S   = features.index('Flow Bytes/s')
IDX_FLOW_PACKETS_S = features.index('Flow Packets/s')

# قيم استبدال حقيقية من training data (df_balanced_C.parquet)
REPLACEMENT_BYTES_S   = 1469750000.0   # max حقيقي في التدريب
REPLACEMENT_PACKETS_S = 4000000.0      # max حقيقي في التدريب

# ── Batch settings ─────────────────────────────────────────
BATCH_SIZE     = 64     # أقصى عدد flows في batch واحد
BATCH_WAIT_SEC = 0.05   # أقصى وقت انتظار قبل عمل predict (50ms)

# ── Confidence threshold ────────────────────────────────────
UNCERTAIN_THRESHOLD = 0.95  # أقل من ده → Uncertain

# ── Event loop ثابت للـ broadcast ─────────────────────────
main_loop = None

def dispatch_alert(alert):
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(ingest_alert(alert), main_loop)
    else:
        logger.error("[Error] Event loop is not running. Cannot dispatch alert.")

# ── Queue للـ raw lines القادمة من Java ───────────────────
flow_queue = queue.Queue()

# ── FastAPI Lifespan ──────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()
    database.init_db()
    
    async def async_insert_and_broadcast(payload):
        # 1. Save to SQLite database
        await asyncio.to_thread(database.insert_alert, payload)
        
        # 2. Format the aggregated payload for the Frontend UI
        hit_count = int(payload.get("hit_count", 1) or 1)
        attack_type = payload.get("attack_type") or payload.get("label", "")
        
        severity = "LOW"
        if hit_count > 100: severity = "CRITICAL"
        elif hit_count > 10: severity = "HIGH"
        elif hit_count > 1: severity = "MEDIUM"
        
        alert_to_send = {
            "id": payload.get("id") or str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "signature": payload.get("classification") or payload.get("signature", ""),
            "srcIp": payload.get("src_ip") or payload.get("srcIp"),
            "dstIp": payload.get("dst_ip") or payload.get("dstIp"),
            "protocol": payload.get("proto") or payload.get("protocol"),
            "action": "aggregated",
            "is_attack": True,
            "label": attack_type,
            "source": payload.get('detection_source', 'ML'),
            "is_pcap": int(payload.get("is_pcap", 0) or 0),
            "hit_count": hit_count
        }
        
        # 3. Broadcast directly to connected WebSockets!
        await broadcast(alert_to_send)

    init_aggregator(async_insert_fn=async_insert_and_broadcast)
    # Using 'any' interface allows Snort to catch attacks tested locally on the same VM (loopback) 
    # as well as external attacks on ens33.
    snort_controller.start_live_mode(interface="ens33")
    threading.Thread(target=socket_listener, daemon=True).start()
    threading.Thread(target=batch_worker, daemon=True).start()
    threading.Thread(target=network_tracker.monitor_task, daemon=True).start()
    logger.info("[Startup] Snort, Socket listener + batch worker + traffic monitor threads started!")
    yield
    logger.info("[Shutdown] Server shutting down...")
    stop_event.set()
    await asyncio.sleep(0.5) # Give worker thread time to exit gracefully
    await shutdown_aggregator()
    snort_controller.stop()

# ── FastAPI ───────────────────────────────────────────────
app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ── Auth & Rate Limiting ──────────────────────────────────
login_attempts = {}

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(login_data: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host
    now = time.time()
    
    # Simple Rate Limiting: max 5 failed attempts per minute
    if client_ip in login_attempts:
        attempts, lock_time = login_attempts[client_ip]
        if lock_time and now - lock_time < 60:
            raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
        elif lock_time and now - lock_time >= 60:
            login_attempts[client_ip] = (0, None) # Reset lock
    else:
        login_attempts[client_ip] = (0, None)
        
    user = database.verify_user(login_data.username, login_data.password)
    if not user:
        # Increment failed attempts
        attempts, lock_time = login_attempts[client_ip]
        attempts += 1
        if attempts >= 5:
            login_attempts[client_ip] = (attempts, now)
        else:
            login_attempts[client_ip] = (attempts, None)
            
        system_logger.log_event(
            level="WARNING",
            component="Auth",
            message=f"Failed login attempt for user '{login_data.username}' from {client_ip}"
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    # Reset attempts on success
    login_attempts[client_ip] = (0, None)
    
    # Generate Token
    token_data = {"sub": str(user["id"]), "role": user["role"]}
    token = auth.create_access_token(token_data)
    
    # Set HttpOnly Cookie
    response.set_cookie(
        key="auth_token",
        value=token,
        httponly=True,
        max_age=3600, # 1 hour
        samesite="lax",
        secure=False # Set to True in production with HTTPS
    )
    
    system_logger.log_event(
        level="INFO",
        component="Auth",
        message=f"Successful login for user '{login_data.username}' (Role: {user['role']}) from {client_ip}"
    )
    
    return {"message": "Login successful", "user": user}

@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(key="auth_token")
    return {"message": "Logged out successfully"}

@app.get("/api/verify-session")
def verify_session(user = Depends(auth.get_current_user)):
    return {"user": user}


clients = []
log_clients = set()
MAX_IN_MEMORY_ALERTS = 5000
alerts  = deque(maxlen=MAX_IN_MEMORY_ALERTS)

# ── Dashboard Stats State ──────────────────────────────────
network_tracker = NetworkTracker(alerts, flow_queue)
snort_controller = SnortController()


# ── تجهيز سطر واحد لـ array جاهز للـ scaling ───────────────
def preprocess_line(csv_line: str):
    try:
        X = np.fromstring(csv_line, dtype=np.float64, sep=',').reshape(1, -1)
    except ValueError:
        print("[WARN] Failed to parse CSV line to floats.")
        return None

    if X.shape[1] != N:
        print(f"[WARN] Expected {N} features, got {X.shape[1]}")
        return None

    # ── 1. معالجة inf في الـ features المعروفة (single-packet flows) ──
    if np.isinf(X[0, IDX_FLOW_BYTES_S]):
        X[0, IDX_FLOW_BYTES_S] = REPLACEMENT_BYTES_S
    if np.isinf(X[0, IDX_FLOW_PACKETS_S]):
        X[0, IDX_FLOW_PACKETS_S] = REPLACEMENT_PACKETS_S

    # ── 2. Safety net عام: أي inf/NaN غير متوقع → 0 ──
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    return X  # shape (1, N) — لسه من غير scaling


# ── Batch Predict ──────────────────────────────────────────
def predict_batch(flow_dicts: list):
    valid_rows = []
    results = []
    metadata_list = []

    for flow_data in flow_dicts:
        try:
            line = flow_data.get("features", "")
            x = preprocess_line(line)
            if x is not None:
                valid_rows.append(x)
                metadata_list.append(flow_data.get("metadata", {}))
        except Exception as e:
            print(f"[ERROR] preprocess: {e}")

    if not valid_rows:
        return results

    # ── 3. Scaling لكل الـ batch مرة واحدة ──
    X = np.vstack(valid_rows)                      # shape (B, N)
    X_scaled = scaler.transform(X).astype('float32')
    X_scaled = np.clip(X_scaled, -10, 10)

    # ── 4. Reshape للموديل (B, N, 1) ──
    X_input = X_scaled.reshape(-1, N, 1).astype('float32')

    # ── 5. Predict على الـ batch كامل مرة واحدة ──
    with model_lock:
        preds = model(X_input, training=False).numpy()

    for i, pred in enumerate(preds):
        idx   = int(np.argmax(pred))
        label = le.inverse_transform([idx])[0]
        conf  = float(pred[idx])

        if conf < UNCERTAIN_THRESHOLD:
            display_label = "Uncertain"
            is_attack_val = None  # غير محدد
        else:
            display_label = label
            is_attack_val = bool(label != "Benign")

        severity = "LOW"
        if is_attack_val:
            if conf > 0.9: severity = "CRITICAL"
            elif conf > 0.7: severity = "HIGH"
            else: severity = "MEDIUM"
        
        meta = metadata_list[i]
        src_ip = meta.get("srcIp", "Unknown")
        src_port = meta.get("srcPort", 0)
        dst_ip = meta.get("dstIp", "Unknown")
        dst_port = meta.get("dstPort", 0)
        protocol = meta.get("protocol", "Unknown")
        
        # ── Correlation Logic: Check Snort Cache ──
        snort_alert = snort_controller.get_alert(src_ip, dst_ip, src_port, dst_port, protocol)
        
        snort_gid_sid = ""
        if snort_alert:
            severity = "CRITICAL"
            is_attack_val = True
            
            # Extract the actual Snort attack name from the JSON
            snort_msg = snort_alert.get("msg", "Snort Alert")
            snort_rule = snort_alert.get("rule", "")
            if snort_rule:
                snort_gid_sid = snort_rule.rsplit(":", 1)[0]
            
            if display_label == "Benign":
                display_label = f"Snort: {snort_msg}"
                detection_source = "SNORT"
            else:
                display_label = f"{display_label} + {snort_msg}"
                detection_source = "HYBRID"
        else:
            detection_source = "ML"
        
        # Use Python's server time to avoid Java's 12-hour format bugs and ensure proper formatting
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        results.append({
            "id": f"ALT-{str(uuid.uuid4())[:8].upper()}",
            "label"     : display_label,
            "raw_label" : label,           
            "confidence": round(conf * 100, 2),
            "timestamp" : timestamp,
            "is_attack" : is_attack_val,
            "severity": severity,
            "signature": display_label,
            "signatureId": snort_gid_sid,
            "category": display_label,
            "srcIp": src_ip,
            "srcPort": src_port,
            "dstIp": dst_ip,
            "dstPort": dst_port,
            "protocol": protocol,
            "action": "Blocked" if is_attack_val else "Allowed",
            "snort_alert": snort_alert,
            "detection_source": detection_source,
            "is_pcap": 0
        })

    return results


# ── Broadcast to all connected WebSocket clients ──────────
async def broadcast(result: dict):
    if not clients:
        return
    msg  = json.dumps(result)
    dead = []
    for ws in list(clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in clients:
            clients.remove(ws)


# ── Event loop دائم لتشغيل الـ broadcast من thread الـ socket ──

async def broadcast_system_log(log_entry: dict):
    """Push high-priority system logs to the React frontend via WebSocket."""
    if not log_clients:
        return
    msg = json.dumps(log_entry)
    dead = set()
    for ws in list(log_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    for ws in dead:
        log_clients.discard(ws)

def emit_system_log(level: str, component: str, message: str, ip: str = None, stack_trace: str = None, raw_payload=None):
    """Legacy function kept for compatibility if called directly."""
    system_logger.log_event(level, component, message, ip, stack_trace, raw_payload)




# ── Worker Thread: بيسحب lines من الـ queue ويعمل batch predict ──
def batch_worker():
    while not stop_event.is_set():
        lines = []
        try:
            # Wait for the first item with optimal latency
            first = flow_queue.get(timeout=BATCH_WAIT_SEC)
            lines.append(first)
        except queue.Empty:
            continue

        # اجمع باقي العناصر الموجودة فعلاً في الـ queue لحد BATCH_SIZE
        while len(lines) < BATCH_SIZE:
            try:
                lines.append(flow_queue.get_nowait())
            except queue.Empty:
                break

        try:
            results = predict_batch(lines)
            for result in results:
                
                # Apply False Positive Suppression Filter
                try:
                    is_suppressed = suppress_false_positive(
                        alert_type=result['label'],
                        protocol=result['protocol'],
                        src_ip=result['srcIp'],
                        src_port=int(result['srcPort']) if str(result['srcPort']).isdigit() else 0,
                        dst_ip=result['dstIp'],
                        dst_port=int(result['dstPort']) if str(result['dstPort']).isdigit() else 0
                    )
                    
                    if is_suppressed:
                        result['is_attack'] = False
                        result['label'] = f"Suppressed ({result['label']})"
                except Exception as e:
                    logger.error(f"[Filter Error] Failed to evaluate suppression: {e}")

                # ONLY store actual attacks in the alerts array and database!
                if result["is_attack"]:
                    alerts.append(result)
                    dispatch_alert(result)  # Fast, Non-blocking via aggregator

                if result['is_attack'] is None:
                    tag = "UNCERT."
                else:
                    tag = "ATTACK" if result['is_attack'] else "Benign"

                extra = f" (raw: {result['raw_label']})" if result['is_attack'] is None else ""
                traffic_info = f"[{result['protocol']}] {result['srcIp']}:{result['srcPort']} -> {result['dstIp']}:{result['dstPort']}"

                # Use print instead of logger so it doesn't go to logs.db or Frontend System Logs
                if tag != "Benign":
                    if result['severity'] in ["HIGH", "CRITICAL"]:
                        print(f"\033[91m[{result['timestamp']}] {tag:7s} | {result['label']:<25s} ({result['confidence']}%){extra} | {traffic_info}\033[0m")
                    else:
                        print(f"\033[93m[{result['timestamp']}] {tag:7s} | {result['label']:<25s} ({result['confidence']}%){extra} | {traffic_info}\033[0m")
                else:
                    # Print Benign in green
                    print(f"\033[92m[{result['timestamp']}] {tag:7s} | {result['label']:<25s} ({result['confidence']}%){extra} | {traffic_info}\033[0m")

                # Only broadcast actual attacks to the frontend WebSocket to save bandwidth
                if result['is_attack']:
                    asyncio.run_coroutine_threadsafe(broadcast(result), main_loop)
        except Exception as e:
            logger.error(f"[Worker Error] batch_worker crashed on predict_batch: {e}")


# ── TCP Socket Listener: Java (LiveCmd) → Python ──────────
def socket_listener():
    HOST, PORT = '127.0.0.1', 65432
    MAX_BUFFER_SIZE = 1024 * 1024 * 5  # 5 MB max buffer
    logger.info(f"[Socket] Waiting for Java CICFlowMeter on {HOST}:{PORT}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)

        while True:
            conn, addr = s.accept()
            # Removed timeout to prevent dropping long-running idle sniffer sessions
            logger.info(f"[Socket] Java connected: {addr}")
            with conn:
                buf = ""
                while True:
                    try:
                        data = conn.recv(8192).decode('utf-8', errors='ignore')
                        if not data:
                            logger.info("[Socket] Java disconnected")
                            break
                        
                        buf += data
                        
                        # Security measure to prevent memory overflow from malformed unbounded streams
                        if len(buf) > MAX_BUFFER_SIZE:
                            logger.warning("[WARN] Socket buffer exceeded max size. Dropping buffer to prevent OOM.")
                            buf = ""
                            continue

                        while '\n' in buf:
                            line, buf = buf.split('\n', 1)
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                flow_data = json.loads(line)
                                meta = flow_data.get("metadata", {})
                                src = str(meta.get("srcIp", ""))
                                dst = str(meta.get("dstIp", ""))
                                if ":" in src or ":" in dst:
                                    continue # Drop IPv6 flows
                                flow_queue.put(flow_data)
                            except json.JSONDecodeError as e:
                                logger.warning(f"[Socket] Malformed JSON dropped: {e}")
                    except socket.timeout:
                        logger.warning("[Socket] Connection timed out. Disconnecting client.")
                        break
                    except Exception as e:
                        logger.error(f"[Socket] Unexpected error: {e}")
                        break


# ── WebSocket endpoint (Frontend) ─────────────────────────
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    logger.info(f"[WS] Frontend connected! clients={len(clients)}")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.remove(websocket)
        logger.info("[WebSocket] Frontend disconnected")

@app.websocket("/ws/system/logs")
async def websocket_system_logs(websocket: WebSocket):
    await websocket.accept()
    log_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        log_clients.discard(websocket)


# ── REST endpoints ─────────────────────────────────────────
@app.get("/status")
def status():
    return {
        "status"  : "running",
        "model"   : "CNN_BiLSTM_Attention_V2",
        "features": N,
        "classes" : list(le.classes_),
        "clients" : len(clients),
        "alerts_total": len(alerts),
        "queue_size": flow_queue.qsize(),
        "uncertain_threshold": UNCERTAIN_THRESHOLD,
    }


@app.get("/alerts")
def get_alerts(limit: int = 50):
    return {"total": len(alerts), "alerts": alerts[-limit:]}

from fastapi import Query

@app.get("/api/alerts")
def get_api_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=1000),
    severity: str = "ALL",
    search: str = "",
    sortOrder: str = "desc",
    origin: str = "ALL",
    user = Depends(auth.get_current_user)
):
    return database.get_alerts(page=page, limit=limit, severity=severity, search=search, sort_order=sortOrder, origin=origin)

@app.get("/api/system/logs")
def get_system_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=1000),
    level: str = "ALL",
    component: str = "ALL",
    admin_user = Depends(auth.require_admin)
):
    offset = (page - 1) * limit
    return system_logger.get_logs(limit=limit, offset=offset, level=level, component=component)


# ── Dashboard API ──────────────────────────────────────────
@app.get("/api/system/info")
def get_system_info(user = Depends(auth.get_current_user)):
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime = (datetime.utcnow() - network_tracker.server_start).total_seconds()
    
    return {
        "success": True,
        "system": {
            "cpu_percent": round(cpu_percent, 1),
            "memory_percent": memory.percent,
            "disk_percent": round((disk.used / disk.total) * 100, 1),
            "uptime_formatted": str(timedelta(seconds=int(uptime))),
        },
        "ml_pipeline": {
            "loaded": True,
            "buffer_status": flow_queue.qsize()
        },
        "capture": {
            "running": True,
            "interface": "auto"
        }
    }

@app.get("/api/dashboard/stats")
def get_dashboard_stats():
    # Alert Counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(alerts)}
    for a in list(alerts):
        sev = a.get("severity", "LOW").lower()
        if sev in counts:
            counts[sev] += 1
            


    active_conns = network_tracker.get_active_connections()
    conns_status = "normal"
    if active_conns > 1000:
        conns_status = "critical"
    elif active_conns > 150:
        conns_status = "warning"

    total_attacks = len([a for a in alerts if a.get("is_attack")])
    networkStats = [
        {"label": "Total Attacks", "value": total_attacks, "unit": "", "change": 0, "status": "warning" if total_attacks > 0 else "normal"},
        {"label": "Active Connections", "value": active_conns, "unit": "conns", "change": 0, "status": conns_status},
        {"label": "Response Time", "value": 15, "unit": "ms", "change": 0, "status": "normal"}
    ]
    
    # Top Attackers
    attackers_map = {}
    for a in list(alerts):
        if a.get("is_attack"):
            ip = a.get("srcIp", "Unknown")
            if ip not in attackers_map:
                attackers_map[ip] = {"ip": ip, "country": "Unknown", "attacks": 0, "lastSeen": a["timestamp"], "type": a["category"]}
            attackers_map[ip]["attacks"] += 1
            attackers_map[ip]["lastSeen"] = a["timestamp"]
    
    topAttackers = sorted(list(attackers_map.values()), key=lambda x: x["attacks"], reverse=True)[:8]

    return {
        "alertCounts": counts,
        "networkStats": networkStats,
        "trafficData": network_tracker.traffic_history if network_tracker.traffic_history else [{"time": datetime.now().strftime("%H:%M"), "normal": 0, "suspicious": 0, "malicious": 0}],
        "throughputData": network_tracker.throughput_history if network_tracker.throughput_history else [{"time": datetime.now().strftime("%H:%M"), "inbound": 0, "outbound": 0}],
        "topAttackers": topAttackers,
        "liveAlerts": list(reversed(list(alerts)[-5:]))
    }

@app.get("/api/aggregator/metrics")
async def get_aggregator_metrics():
    return get_metrics()

@app.get("/api/network/dashboard")
def get_network_dashboard():
    # Calculate current inbound/outbound mbps from the latest history or 0
    inbound_mbps = 0
    outbound_mbps = 0
    if network_tracker.throughput_history:
        latest = network_tracker.throughput_history[-1]
        inbound_mbps = latest.get("inbound", 0)
        outbound_mbps = latest.get("outbound", 0)
        
    return {
        "stats": {
            "inboundMbps": inbound_mbps,
            "outboundMbps": outbound_mbps,
            "activeConnections": network_tracker.get_active_connections(),
            "blockedIps": 0 # Blocked IPs are set to 0 as per user request
        },
        "connectionData": network_tracker.throughput_history if network_tracker.throughput_history else [{"time": datetime.now().strftime("%H:%M"), "inbound": 0, "outbound": 0}],
        "protocolData": network_tracker.get_protocols_distribution(),
        "activeConnections": network_tracker.get_active_connections_list(limit=20)
    }

@app.post("/api/analyze/file")
def analyze_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    # Create temp directory
    temp_dir = f"/tmp/pcap_uploads_{uuid.uuid4().hex[:8]}"
    os.makedirs(temp_dir, exist_ok=True)
    
    file_path = os.path.join(temp_dir, file.filename)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        is_csv = file.filename.lower().endswith(".csv")
        csv_path = file_path
        
        if not is_csv:
            # Ensure PCAP file is processed by Snort offline engine before ML inference
            logger.info(f"[Snort] Initiating offline PCAP analysis for {file_path}")
            snort_summary = snort_controller.start_pcap_mode(file_path)
            
            csv_path = extract_flows_from_pcap(file_path, temp_dir)
            if not csv_path:
                return {"error": "Failed to extract flows from PCAP"}
        else:
            snort_summary = {"ran": False, "alerts_found": 0, "rules_matched": []}
                
        # Process CSV
        df = pd.read_csv(csv_path)
        df.columns = df.columns.str.strip() # Remove spaces from headers
        total_flows = len(df)
        
        if total_flows == 0:
            return {"error": "No flows found"}
            
        # Check if all required features exist
        missing = [f for f in features if f not in df.columns]
        if missing:
            return {"error": f"Missing features in CSV: {missing[:5]}"}
            
        # Extract the exact 65 features as a numpy array
        X_batch = df[features].values.astype('float64')
        
        print("\n" + "="*50)
        print("[DEBUG] OFF-LINE PCAP ANALYSIS - FEATURE VERIFICATION")
        print(f"[DEBUG] Total Flows Found: {total_flows}")
        print(f"[DEBUG] Features Matched: {len(features)} / 65")
        print(f"[DEBUG] X_batch shape before processing: {X_batch.shape}")
        
        # Print ALL 65 features for the first flow to verify order
        print("\n[DEBUG] --- FULL FEATURE MAP FOR FLOW 1 ---")
        for idx, feat_name in enumerate(features):
            print(f"   [{idx+1:02d}/65] {feat_name:<30}: {X_batch[0][idx]}")
        
        # Save a debug CSV to disk so you can inspect it easily
        debug_df = pd.DataFrame(X_batch[:10], columns=features)
        debug_df.to_csv('debug_features_sample.csv', index=False)
        print("\n[DEBUG] Saved first 10 flows raw features to 'backend/debug_features_sample.csv'")
        print("="*50 + "\n")
        
        # 1. Handle inf
        mask_bytes = np.isinf(X_batch[:, IDX_FLOW_BYTES_S])
        X_batch[mask_bytes, IDX_FLOW_BYTES_S] = REPLACEMENT_BYTES_S
        
        mask_packets = np.isinf(X_batch[:, IDX_FLOW_PACKETS_S])
        X_batch[mask_packets, IDX_FLOW_PACKETS_S] = REPLACEMENT_PACKETS_S
        
        # 2. Safety net for NaNs
        X_batch = np.nan_to_num(X_batch, nan=0.0, posinf=0.0, neginf=0.0)
        
        # 3. Scaling
        X_scaled = scaler.transform(X_batch).astype('float32')
        X_scaled = np.clip(X_scaled, -10, 10)
        
        # 4. Reshape
        X_input = X_scaled.reshape(-1, N, 1).astype('float32')
        print(f"[DEBUG] X_input shape for model: {X_input.shape}")
        print("="*50 + "\n")
        
        # 5. Predict in chunks to avoid memory explosion on huge PCAPs
        BATCH_INFERENCE = 1024
        all_preds = []
        for i in range(0, len(X_input), BATCH_INFERENCE):
            chunk = X_input[i:i+BATCH_INFERENCE]
            with model_lock:
                chunk_preds = model(chunk, training=False).numpy()
            all_preds.append(chunk_preds)
            
        all_preds = np.vstack(all_preds)
        
        alerts = []
        attack_counts = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        protocols = {}
        top_src_ips = {}
        top_dst_ips = {}
        detection_breakdown = {"signature": 0, "ml": 0}
        
        # Read IP metadata if available
        src_ips = df['Src IP'].values if 'Src IP' in df.columns else ['Unknown'] * total_flows
        dst_ips = df['Dst IP'].values if 'Dst IP' in df.columns else ['Unknown'] * total_flows
        src_ports = df['Src Port'].values if 'Src Port' in df.columns else [0] * total_flows
        dst_ports = df['Dst Port'].values if 'Dst Port' in df.columns else [0] * total_flows
        
        # Advanced Debugging Stats
        raw_predictions = {}
        uncertain_count = 0
        avg_confidence = {}
        
        for i, pred in enumerate(all_preds):
            idx   = int(np.argmax(pred))
            label = le.inverse_transform([idx])[0]
            conf  = float(pred[idx])
            
            # Capture stats before any thresholding
            if label not in raw_predictions:
                raw_predictions[label] = 0
                avg_confidence[label] = []
            raw_predictions[label] += 1
            avg_confidence[label].append(conf)
            
            src = str(src_ips[i])
            dst = str(dst_ips[i])
            
            # Skip IPv6 flows
            if ":" in src or ":" in dst:
                continue
            
            if conf < UNCERTAIN_THRESHOLD:
                uncertain_count += 1
                
            src = str(src_ips[i])
            dst = str(dst_ips[i])
            sp = str(src_ports[i])
            dp = str(dst_ports[i])
            
            top_src_ips[src] = top_src_ips.get(src, 0) + 1
            top_dst_ips[dst] = top_dst_ips.get(dst, 0) + 1
            
            proto_num = int(X_batch[i, 1]) # Index 1 is Protocol
            proto = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else "Other"))
            protocols[proto] = protocols.get(proto, 0) + 1
            
            # Correlation Logic Check
            snort_alert = snort_controller.get_alert(src, dst, sp, dp, proto)
            is_attack = False
            
            if conf >= UNCERTAIN_THRESHOLD and label != "Benign":
                is_attack = True
                detection_breakdown["ml"] += 1
                
            snort_gid_sid = ""
            if snort_alert:
                is_attack = True
                detection_breakdown["signature"] += 1
                label = f"{label} + Snort" if label != "Benign" else "Snort Alert"
                
                snort_rule = snort_alert.get("rule", "")
                if snort_rule:
                    snort_gid_sid = snort_rule.rsplit(":", 1)[0]
                
            if is_attack:
                attack_counts[label] = attack_counts.get(label, 0) + 1
                
                severity = "LOW"
                if snort_alert or conf > 0.9: severity = "CRITICAL"
                elif conf > 0.7: severity = "HIGH"
                else: severity = "MEDIUM"
                
                severity_counts[severity.lower()] += 1
                
                if snort_alert:
                    detection_source = "SNORT" if label.startswith("Snort Alert") else "HYBRID"
                else:
                    detection_source = "ML"

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                res_alert = {
                    "id": f"ALT-{str(uuid.uuid4())[:8].upper()}",
                    "label": label,
                    "raw_label": label,
                    "confidence": round(conf * 100, 2),
                    "timestamp": timestamp,
                    "is_attack": True,
                    "severity": severity,
                    "signature": f"Offline PCAP: {label}",
                    "signatureId": snort_gid_sid,
                    "category": label,
                    "srcIp": src,
                    "srcPort": sp,
                    "dstIp": dst,
                    "dstPort": dp,
                    "protocol": proto,
                    "action": "Blocked",
                    "snort_alert": snort_alert,
                    "detection_source": detection_source,
                    "is_pcap": 1
                }
                alerts.append(res_alert)
                dispatch_alert(res_alert)
                
        # Print the Advanced Debugging Stats
        print("\n" + "="*50)
        print("[DEBUG] OFF-LINE PCAP PREDICTION STATS")
        print(f"[DEBUG] Total Flows Processed: {total_flows}")
        print(f"[DEBUG] Uncertain Flows (confidence < {UNCERTAIN_THRESHOLD}): {uncertain_count}")
        print("[DEBUG] Raw Model Predictions (Before Thresholding):")
        for lbl, count in raw_predictions.items():
            avg_c = sum(avg_confidence[lbl]) / len(avg_confidence[lbl])
            print(f"   - {lbl}: {count} flows (Avg Confidence: {avg_c:.4f})")
        print("="*50 + "\n")
                
        # Format for frontend
        formatted_protocols = []
        for k, v in protocols.items():
            formatted_protocols.append({"name": k, "count": v, "percentage": round((v/total_flows)*100, 1)})
            
        formatted_top_src = [{"ip": k, "packets": v} for k, v in sorted(top_src_ips.items(), key=lambda x: x[1], reverse=True)[:5]]
        formatted_top_dst = [{"ip": k, "packets": v} for k, v in sorted(top_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]]
        
        threats = []
        for k, v in attack_counts.items():
            # Estimate severity based on attack type or default to HIGH
            threats.append({
                "name": k,
                "count": v,
                "severity": "CRITICAL" if v > 100 else "HIGH"
            })
            
        return {
            "success": True,
            "total_flows": total_flows,
            "benign_flows": total_flows - len(alerts),
            "alerts_found": len(alerts),
            "attack_types": attack_counts,
            "severity_distribution": severity_counts,
            "snort_summary": snort_summary,
            "detection_breakdown": detection_breakdown,
            "totalPackets": total_flows,
            "suspiciousPackets": len(alerts),
            "protocols": formatted_protocols,
            "topSourceIPs": formatted_top_src,
            "topDestIPs": formatted_top_dst,
            "threats": threats,
            "alerts": alerts[:100]
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ── Clear Databases Endpoint (Testing & Debugging) ─────────
@app.delete("/api/clear_databases")
async def clear_databases(target: str = "both", admin_user = Depends(auth.require_admin)):
    """
    Endpoint to clear entries from databases.
    ?target=alerts : Clears only alerts.db (and memory cache)
    ?target=logs   : Clears only logs.db
    ?target=both   : Clears both
    """
    import sqlite3
    import os
    global alerts
    
    base_dir = os.path.dirname(__file__)
    alerts_db = os.path.join(base_dir, "alerts.db")
    logs_db = os.path.join(base_dir, "logs.db")
    
    status = []
    
    try:
        # Clear alerts.db
        if target in ["alerts", "both"]:
            if os.path.exists(alerts_db):
                conn = sqlite3.connect(alerts_db)
                conn.execute("DELETE FROM alerts")
                conn.commit()
                conn.close()
            alerts.clear()  # Clear in-memory cache as well
            status.append("alerts.db cleared")
            
        # Clear logs.db
        if target in ["logs", "both"]:
            if os.path.exists(logs_db):
                conn = sqlite3.connect(logs_db)
                conn.execute("DELETE FROM system_logs")
                conn.commit()
                conn.close()
            status.append("logs.db cleared")
            
        if not status:
            return {"success": False, "error": "Invalid target. Use 'alerts', 'logs', or 'both'."}
            
        return {"success": True, "message": " | ".join(status)}
    except Exception as e:
        logger.error(f"[DB] Error clearing databases: {e}")
        return {"success": False, "error": str(e)}