"""
backend/core/aggregator.py
==========================
Single-file alert aggregation module.

Usage in inference_server.py
----------------------------
    from core.aggregator import init_aggregator, ingest_alert, shutdown_aggregator

    @asynccontextmanager
    async def lifespan(app):
        init_aggregator(insert_alert_fn=insert_alert)   # sync DB function
        yield
        await shutdown_aggregator()

    # anywhere in your code where you used to call `insert_alert(...)`:
    await ingest_alert(alert_dict)

What it does
------------
• Filters Benign / UNCERT. / low-confidence alerts
• Drops ML hallucinations (SQLi over UDP/53, SSH-Bruteforce on wrong port)
• Smart cache key per attack family:
    - scan  : (src, dst, attack_type)         -> collapses port scans
    - brute : (src, dst, port, attack_type)   -> keeps port for brute force
    - flood : (dst, attack_type)              -> collapses multi-source DDoS
• Sliding window (extends on each hit) + hard lifetime cap
• MIN_HITS threshold drops single-packet noise
• Background sweeper flushes to DB every 2s
• Graceful shutdown drains the cache
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, Dict, Optional

logger = logging.getLogger("aggregator")

# ---------------------------------------------------------------------------
# Tunables — override at init() time if needed
# ---------------------------------------------------------------------------
AGGREGATION_WINDOW      = 10.0
MAX_WINDOW_LIFETIME     = 60.0
MIN_HITS_TO_PERSIST     = 3
MAX_HITS_PER_AGGREGATE  = 5000
SWEEPER_INTERVAL        = 2.0
MIN_CONFIDENCE          = 80.0

# ---------------------------------------------------------------------------
# Attack-family routing
# ---------------------------------------------------------------------------
ATTACK_FAMILY: Dict[str, str] = {
    # scans -> port varies, collapse it
    "Reconnaissance":       "scan",
    "Port Scan":            "scan",
    "TCP portscan":         "scan",
    "UDP portscan":         "scan",
    "SYN Scan":             "scan",
    "FIN Scan":             "scan",
    "Xmas Scan":            "scan",

    # brute force / single-port targeted attacks -> keep port
    "SSH-Bruteforce":       "brute",
    "FTP-Bruteforce":       "brute",
    "SMTP-Bruteforce":      "brute",
    "HTTP-Bruteforce":      "brute",
    "RDP-Bruteforce":       "brute",
    "Telnet-Bruteforce":    "brute",
    "SQL Injection":        "brute",
    "XSS":                  "brute",
    "Command Injection":    "brute",

    # flood / DDoS -> many sources, drop src_ip
    "HTTP-Flood":           "flood",
    "SYN-Flood":            "flood",
    "UDP-Flood":            "flood",
    "ICMP-Flood":           "flood",
    "DDoS":                 "flood",
}


def _family_of(attack_type: str, classification: str) -> str:
    key = (attack_type or "").strip()
    if key in ATTACK_FAMILY:
        return ATTACK_FAMILY[key]
    cls = (classification or "").lower()
    if "portscan" in cls or "recon" in cls:
        return "scan"
    if "bruteforce" in cls or "brute" in cls:
        return "brute"
    if "flood" in cls or "ddos" in cls:
        return "flood"
    return "generic"


def _build_key(a: Dict[str, Any], family: str) -> str:
    src_ip      = a.get("src_ip", "")
    dst_ip      = a.get("dst_ip", "")
    dst_port    = a.get("dst_port", "")
    attack_type = a.get("attack_type", "")
    is_pcap     = a.get("is_pcap", 0)

    if family == "scan":
        return f"{src_ip}|{dst_ip}|{attack_type}|{is_pcap}"
    if family == "brute":
        return f"{src_ip}|{dst_ip}|{dst_port}|{attack_type}|{is_pcap}"
    if family == "flood":
        return f"{dst_ip}|{attack_type}|{is_pcap}"
    return f"{src_ip}|{dst_ip}|{dst_port}|{attack_type}|{is_pcap}"


# ---------------------------------------------------------------------------
# Module state — populated by init_aggregator()
# ---------------------------------------------------------------------------
_cache: Dict[str, dict]                          = {}
_lock: Optional[asyncio.Lock]                    = None
_insert_fn: Optional[Callable[[dict], Any]]      = None   # sync DB function
_async_insert_fn: Optional[Callable[[dict], Awaitable[Any]]] = None  # async DB function
_sweeper_task: Optional[asyncio.Task]            = None
_metrics: Dict[str, int] = {
    "received":         0,
    "dropped_benign":   0,
    "dropped_low_conf": 0,
    "dropped_rule":     0,
    "dropped_noise":    0,
    "aggregated_hits":  0,
    "flushed":          0,
    "errors":           0,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def init_aggregator(
    insert_alert_fn: Optional[Callable[[dict], Any]] = None,
    async_insert_fn: Optional[Callable[[dict], Awaitable[Any]]] = None,
) -> None:
    """
    Initialise the aggregator and start the background sweeper.

    Pass either:
      insert_alert_fn  — a SYNCHRONOUS DB insert function (will run in a thread)
      async_insert_fn  — an ASYNC DB insert function (awaited directly)
    """
    global _lock, _insert_fn, _async_insert_fn, _sweeper_task

    if _sweeper_task is not None and not _sweeper_task.done():
        logger.warning("init_aggregator() called twice — ignoring second call")
        return

    _lock            = asyncio.Lock()
    _insert_fn       = insert_alert_fn
    _async_insert_fn = async_insert_fn

    if _insert_fn is None and _async_insert_fn is None:
        logger.warning("Aggregator initialised without a DB function — using stdout")
        def _stdout(payload: dict) -> None:
            print(f"[FLUSH] {payload.get('attack_type')} "
                  f"{payload.get('src_ip')} -> {payload.get('dst_ip')} "
                  f"hits={payload.get('hit_count')} ports={payload.get('port_count')}")
        _insert_fn = _stdout

    _sweeper_task = asyncio.create_task(_sweeper_loop())
    logger.info("Aggregator initialised (window=%.1fs, min_hits=%d)",
                AGGREGATION_WINDOW, MIN_HITS_TO_PERSIST)


async def ingest_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process one alert. Returns a small status dict (useful for debugging).
    Never raises.
    """
    if _lock is None:
        # auto-init in dev mode if someone forgot to call init_aggregator()
        init_aggregator()

    _metrics["received"] += 1

    attack_type    = (alert.get("attack_type") or "").strip()
    classification = (alert.get("classification") or "").strip()
    confidence     = float(alert.get("confidence", 100.0) or 0.0)

    # 0) drop Benign traffic
    if attack_type.lower() == "benign" or classification.lower() == "benign":
        _metrics["dropped_benign"] += 1
        return {"status": "dropped", "reason": "benign"}

    # 1) drop low confidence / uncertain
    if "UNCERT." in classification or confidence < MIN_CONFIDENCE:
        _metrics["dropped_low_conf"] += 1
        return {"status": "dropped", "reason": "low_confidence"}

    # 2) rule-based ML hallucination filters
    proto    = (alert.get("proto") or "").upper()
    dst_port = alert.get("dst_port")
    if attack_type == "SQL Injection" and proto == "UDP" and dst_port == 53:
        _metrics["dropped_rule"] += 1
        return {"status": "dropped", "reason": "sql_over_udp53"}
    if attack_type == "SSH-Bruteforce" and dst_port not in (22, 2222):
        _metrics["dropped_rule"] += 1
        return {"status": "dropped", "reason": "ssh_wrong_port"}

    # 3) smart cache key
    family = _family_of(attack_type, classification)
    key    = _build_key(alert, family)
    now    = time.time()

    # 4) critical section — short, pure Python
    async with _lock:
        entry = _cache.get(key)
        if entry is None:
            _cache[key] = {
                **alert,
                "hit_count":      1,
                "first_seen":     now,
                "last_seen":      now,
                "family":         family,
                "targeted_ports": {dst_port} if dst_port is not None else set(),
            }
        else:
            entry["hit_count"] += 1
            entry["last_seen"]  = now
            if dst_port is not None:
                entry["targeted_ports"].add(dst_port)
            _metrics["aggregated_hits"] += 1

            if entry["hit_count"] >= MAX_HITS_PER_AGGREGATE:
                del _cache[key]
                asyncio.create_task(_flush_entry(entry))

    return {"status": "ok", "key": key, "family": family}


async def _flush_entry(entry: dict) -> None:
    """Convert one in-memory entry into a DB row. Called OUTSIDE the lock."""
    if entry["hit_count"] < MIN_HITS_TO_PERSIST:
        _metrics["dropped_noise"] += 1
        return

    ports   = sorted(entry.pop("targeted_ports", set()))
    payload = {**entry}
    payload["targeted_ports"] = ports
    payload["port_count"]     = len(ports)
    payload["duration"]       = entry["last_seen"] - entry["first_seen"]

    try:
        if _async_insert_fn is not None:
            await _async_insert_fn(payload)
        elif _insert_fn is not None:
            await asyncio.to_thread(_insert_fn, payload)
        _metrics["flushed"] += 1
    except Exception:
        _metrics["errors"] += 1
        logger.exception("DB flush failed: %s", payload)


async def _sweeper_loop() -> None:
    """Background task: flush stale entries every SWEEPER_INTERVAL seconds."""
    logger.info("Sweeper started (interval=%.1fs)", SWEEPER_INTERVAL)
    while True:
        try:
            await asyncio.sleep(SWEEPER_INTERVAL)
            now      = time.time()
            to_flush = []

            async with _lock:
                for k, e in list(_cache.items()):
                    idle = now - e["last_seen"]
                    age  = now - e["first_seen"]
                    if idle >= AGGREGATION_WINDOW or age >= MAX_WINDOW_LIFETIME:
                        to_flush.append(e)
                        del _cache[k]

            for e in to_flush:
                await _flush_entry(e)

            if to_flush:
                logger.info("Sweeper flushed %d entries, cache_size=%d",
                            len(to_flush), len(_cache))
        except asyncio.CancelledError:
            logger.info("Sweeper cancelled — draining cache...")
            async with _lock:
                pending = list(_cache.values())
                _cache.clear()
            for e in pending:
                await _flush_entry(e)
            raise
        except Exception:
            logger.exception("Sweeper iteration failed (continuing)")
            await asyncio.sleep(SWEEPER_INTERVAL)


async def shutdown_aggregator() -> None:
    """Cancel the sweeper and flush everything. Call on app shutdown."""
    global _sweeper_task
    if _sweeper_task is None:
        return
    _sweeper_task.cancel()
    try:
        await _sweeper_task
    except asyncio.CancelledError:
        pass
    _sweeper_task = None

    # drain anything still in cache
    async with _lock:
        pending = list(_cache.values())
        _cache.clear()
    for e in pending:
        await _flush_entry(e)
    logger.info("Aggregator shutdown complete. flushed_total=%d", _metrics["flushed"])


def get_metrics() -> Dict[str, int]:
    """Snapshot of internal counters + cache size."""
    return {**_metrics, "cache_size": len(_cache)}
