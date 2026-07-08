import os
import time
import json
import socket
import asyncio
import threading
import subprocess
import logging
import atexit

logger = logging.getLogger("IDS_Backend")

class SnortController:
    """
    Process Management Controller for Snort 3.
    Features: RAM-to-RAM Streaming (stdout), Lazy TTL Expiration, Memory Leak Prevention, and Zombie Process Prevention.
    """
    def __init__(self, ttl=300):
        self.ttl = ttl
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.process = None
        self._stop_event = threading.Event()
        
        # Register safety net to ensure process is killed even if Python crashes abruptly
        atexit.register(self.stop)

    def start_live_mode(self, interface="ens33", config_path="/mnt/extra_storage/IDS_Project/snort.lua"):
        """
        Executes Snort 3 in Live Mode securely using File-Based JSON logging to prevent Pipe Buffer Deadlock.
        """
        self._stop_event.clear()
        
        # Foolproof zombie prevention: Kill any lingering Snort processes from previous bad crashes
        logger.info("[Snort] Cleaning up any old zombie Snort processes...")
        os.system("pkill -9 -f '/usr/local/bin/snort' 2>/dev/null")
        
        # Ensure log file exists and is empty
        log_file = "/var/log/snort/alert_json.txt"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, "w") as f:
            pass
        logger.info(f"[Snort] Launching Snort 3 Live Mode on interface '{interface}'")

        # Command WITHOUT the '-l' flag because alert_json = { file = true } implicitly uses /var/log/snort/
        # The '-q' flag minimizes console spam.
        cmd = [
            "/usr/local/bin/snort",
            "-i", interface,
            "-c", config_path,
            "-l", "/var/log/snort",
            "-q",
            "--lua", "alert_json = { file = true, fields = 'timestamp pkt_num proto src_addr src_port dst_addr dst_port rule msg action' }"
        ]

        try:
            # Launch Snort WITHOUT stdout/stderr pipes! 
            # This completely isolates Snort, preventing OS Pipe Buffer Deadlocks.
            self.process = subprocess.Popen(
                cmd,
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Launch a non-blocking tail process to read the log file asynchronously
            tail_cmd = ["tail", "-F", log_file]
            self.tail_process = subprocess.Popen(
                tail_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            
            # Thread to parse JSON alerts from the tail output
            def read_tail_alerts(proc):
                logger.info("[Snort] Listening for JSON alerts via decoupled log tailing...")
                try:
                    for line in proc.stdout:
                        if self._stop_event.is_set():
                            break
                        line = line.strip()
                        if line:
                            try:
                                alert_data = json.loads(line)
                                self._process_alert(alert_data)
                            except json.JSONDecodeError:
                                # Safely ignore any corrupted or non-JSON log lines
                                pass 
                except Exception as e:
                    if not self._stop_event.is_set():
                        logger.error(f"[Snort Tail Monitor Error] {e}")

            # Start thread as daemon
            threading.Thread(target=read_tail_alerts, args=(self.tail_process,), daemon=True).start()

            logger.info(f"[Snort] Launched Snort 3 Live Mode [PID: {self.process.pid}]")
            
        except Exception as e:
            logger.error(f"[Snort] Failed to launch Snort process: {e}")

    def start_pcap_mode(self, pcap_path, config_path="/mnt/extra_storage/IDS_Project/snort.lua"):
        """
        Executes Snort 3 in PCAP mode offline and returns summary statistics.
        """
        cmd = ["/usr/local/bin/snort", "-r", pcap_path, "-c", config_path, "-q", "--lua", "alert_json = { file = false, fields = 'timestamp pkt_num proto src_addr src_port dst_addr dst_port rule msg action' }"]
        
        snort_summary = {
            "ran": False,
            "alerts_found": 0,
            "rules_matched": []
        }
        
        try:
            logger.info(f"[Snort] Starting offline PCAP analysis: {pcap_path}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            snort_summary["ran"] = True
            
            matched_sids = set()
            
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        alert_data = json.loads(line)
                        self._process_alert(alert_data)
                        
                        snort_summary["alerts_found"] += 1
                        rule = alert_data.get("rule", "")
                        if ":" in rule:
                            sid = rule.split(":")[1]
                            matched_sids.add(int(sid))
                            
                    except json.JSONDecodeError:
                        pass
                        
            snort_summary["rules_matched"] = list(matched_sids)
            logger.info(f"[Snort] Offline PCAP completed. Found {snort_summary['alerts_found']} alerts.")
            return snort_summary
        except Exception as e:
            logger.error(f"[Snort] Failed to analyze PCAP: {e}")
            return snort_summary

    def stop(self):
        """
        Gracefully terminates Snort and tail processes.
        """
        self._stop_event.set()
        
        if hasattr(self, 'tail_process') and self.tail_process.poll() is None:
            self.tail_process.terminate()

        if self.process and self.process.poll() is None:
            logger.info(f"[Snort] Sending SIGTERM to process (PID {self.process.pid})...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
                logger.info("[Snort] Process terminated gracefully.")
            except subprocess.TimeoutExpired:
                logger.warning("[Snort] Process ignored SIGTERM. Escalating to SIGKILL.")
                self.process.kill()
                self.process.wait()
                logger.info("[Snort] Process killed.")

    def _generate_correlation_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        """
        Generates a standardized bidirectional 5-Tuple key.
        """
        src_ip = str(src_ip).strip()
        dst_ip = str(dst_ip).strip()
        src_port = str(src_port).strip()
        dst_port = str(dst_port).strip()
        protocol = str(proto).strip().upper()

        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        elif src_ip > dst_ip:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        else:
            if int(src_port) < int(dst_port):
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def _process_alert(self, alert_data):
        """
        Extracts the 5-Tuple and caches the alert payload.
        Also caches a fallback IP-only key for general alerts like port scans.
        """
        src_ip = alert_data.get("src_addr", "")
        dst_ip = alert_data.get("dst_addr", "")
        src_port = alert_data.get("src_port", "0")
        dst_port = alert_data.get("dst_port", "0")
        proto = alert_data.get("proto", alert_data.get("protocol", "TCP"))

        exact_key = self._generate_correlation_key(src_ip, dst_ip, src_port, dst_port, proto)
        ip_only_key = self._generate_correlation_key(src_ip, dst_ip, "0", "0", proto)
        pure_ip_key = self._generate_correlation_key(src_ip, dst_ip, "0", "0", "ANY")

        with self.cache_lock:
            # Prevent memory leak
            if len(self.cache) > 10000:
                logger.warning("[Snort] Cache overflow. Clearing unqueried alerts.")
                self.cache.clear()

            alert_entry = {
                "timestamp": time.time(),
                "data": alert_data
            }
            self.cache[exact_key] = alert_entry
            
            # For port scans or general alerts, also cache by IP only
            if str(src_port) == "0" or str(dst_port) == "0" or "scan" in str(alert_data.get("rule", "")).lower() or proto == "ICMP":
                self.cache[ip_only_key] = alert_entry
            
            # Bulletproof fallback for lab demo
            self.cache[pure_ip_key] = alert_entry

    def get_alert(self, src_ip, dst_ip, src_port, dst_port, proto):
        """
        Retrieves a correlated Snort alert if it exists.
        Falls back to IP-only matches for general alerts (like Port Scans).
        """
        exact_key = self._generate_correlation_key(src_ip, dst_ip, src_port, dst_port, proto)
        ip_only_key = self._generate_correlation_key(src_ip, dst_ip, "0", "0", proto)
        pure_ip_key = self._generate_correlation_key(src_ip, dst_ip, "0", "0", "ANY")

        with self.cache_lock:
            for key in [exact_key, ip_only_key, pure_ip_key]:
                if key in self.cache:
                    entry = self.cache[key]
                    
                    # Evaluate TTL strictly on access
                    if time.time() - entry["timestamp"] <= self.ttl:
                        return entry["data"]
                    else:
                        # Expired -> Evict from cache
                        del self.cache[key]
            return None
