import time
import psutil
from datetime import datetime, timedelta

class NetworkTracker:
    def __init__(self, alerts_list, flow_queue):
        self.alerts = alerts_list
        self.flow_queue = flow_queue
        self.traffic_history = []
        self.throughput_history = []
        self.active_flood_conns = 0
        self.server_start = datetime.utcnow()
        self._prefill_history()

    def _prefill_history(self):
        for i in range(24, 0, -1):
            t_str = (datetime.now() - timedelta(seconds=i*5)).strftime("%H:%M:%S")
            self.throughput_history.append({"time": t_str, "inbound": 0, "outbound": 0})
            self.traffic_history.append({"time": t_str, "normal": 0, "suspicious": 0, "malicious": 0})

    def _get_external_io(self):
        counters = psutil.net_io_counters(pernic=True)
        b_recv, b_sent, p_recv = 0, 0, 0
        for nic, stats in counters.items():
            if nic != 'lo':
                b_recv += stats.bytes_recv
                b_sent += stats.bytes_sent
                p_recv += stats.packets_recv
        return b_recv, b_sent, p_recv

    def monitor_task(self):
        last_bytes_recv, last_bytes_sent, last_packets_recv = self._get_external_io()
        
        while True:
            try:
                time.sleep(5)
                bytes_recv, bytes_sent, packets_recv = self._get_external_io()
                now_str = datetime.now().strftime("%H:%M:%S")
                
                # Throughput (Mbps) and Packets
                bytes_recv_diff = bytes_recv - last_bytes_recv
                bytes_sent_diff = bytes_sent - last_bytes_sent
                packets_diff = packets_recv - last_packets_recv
                
                last_bytes_recv = bytes_recv
                last_bytes_sent = bytes_sent
                last_packets_recv = packets_recv
                
                # Convert bytes to Megabytes per second (MB/s)
                # 1 Megabyte = 1,048,576 bytes
                inbound_mbps = round((bytes_recv_diff) / (1_048_576 * 5), 2)
                outbound_mbps = round((bytes_sent_diff) / (1_048_576 * 5), 2)
                
                # Estimate spoofed half-open connections during floods (e.g. hping3) 
                if packets_diff > 10000:
                    self.active_flood_conns = int(packets_diff * 0.03) # Approximate 3000 conns per 100k packets
                else:
                    self.active_flood_conns = 0
                
                self.throughput_history.append({
                    "time": now_str,
                    "inbound": inbound_mbps,
                    "outbound": outbound_mbps
                })
                if len(self.throughput_history) > 24:
                    self.throughput_history.pop(0)

                # Traffic
                recent = [a for a in self.alerts if (datetime.now() - datetime.strptime(a.get("timestamp", "2000-01-01 00:00:00"), "%Y-%m-%d %H:%M:%S")).seconds <= 5]
                normal_c = len([a for a in recent if not a.get("is_attack")])
                malicious_c = len([a for a in recent if a.get("is_attack")])
                self.traffic_history.append({
                    "time": now_str,
                    "normal": normal_c * 10, # Multiplied for visual scale
                    "suspicious": 0,
                    "malicious": malicious_c * 10
                })
                if len(self.traffic_history) > 24:
                    self.traffic_history.pop(0)
                    
            except Exception as e:
                print(f"[ERROR] tracker monitor_task: {e}")
                time.sleep(10)

    def get_active_connections(self):
        try:
            base_conns = len(psutil.net_connections())
            recent_count = len([a for a in self.alerts if (datetime.now() - datetime.strptime(a.get("timestamp", "2000-01-01 00:00:00"), "%Y-%m-%d %H:%M:%S")).seconds <= 10])
            return base_conns + recent_count + self.flow_queue.qsize() + self.active_flood_conns
        except Exception:
            return 0

    def get_protocols_distribution(self):
        try:
            import socket
            conns = psutil.net_connections(kind='inet')
            counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
            
            for c in conns:
                if c.type == socket.SOCK_STREAM:
                    counts["TCP"] += 1
                elif c.type == socket.SOCK_DGRAM:
                    counts["UDP"] += 1
                else:
                    counts["Other"] += 1
                    
            total = sum(counts.values())
            if total == 0:
                # Fallback baseline
                return [
                    {"name": "TCP", "value": 60, "color": "#06b6d4"},
                    {"name": "UDP", "value": 30, "color": "#22c55e"},
                    {"name": "ICMP", "value": 5, "color": "#eab308"},
                    {"name": "Other", "value": 5, "color": "#8b5cf6"}
                ]
                
            return [
                {"name": "TCP", "value": round((counts["TCP"]/total)*100, 1), "color": "#06b6d4"},
                {"name": "UDP", "value": round((counts["UDP"]/total)*100, 1), "color": "#22c55e"},
                {"name": "ICMP", "value": round((counts["ICMP"]/total)*100, 1), "color": "#eab308"},
                {"name": "Other", "value": round((counts["Other"]/total)*100, 1), "color": "#8b5cf6"}
            ]
        except Exception:
            return []

    def get_active_connections_list(self, limit=50):
        try:
            import socket
            conns = psutil.net_connections(kind='inet')
            
            # Build a set of ports that are actively listening for incoming connections
            listen_ports = set()
            for c in conns:
                if c.status == 'LISTEN':
                    listen_ports.add(c.laddr.port)
                elif c.type == socket.SOCK_DGRAM and not c.raddr:
                    listen_ports.add(c.laddr.port)
            
            # Fallback well-known ports just in case
            listen_ports.update([22, 53, 80, 443, 8000, 8080])

            result = []
            
            for c in conns:
                if not c.laddr or not c.raddr:
                    continue
                    
                protocol = "TCP" if c.type == socket.SOCK_STREAM else "UDP" if c.type == socket.SOCK_DGRAM else "Other"
                
                # Real technical detection based on actual socket state:
                # If our local port is one of the listening ports, then someone connected to US (Inbound)
                if c.laddr.port in listen_ports:
                    # Inbound: We are the server
                    src_ip = c.raddr.ip
                    dst_ip = c.laddr.ip
                    srv_port = c.laddr.port
                else:
                    # Outbound: We are the client, the remote port is the target service
                    src_ip = c.laddr.ip
                    dst_ip = c.raddr.ip
                    srv_port = c.raddr.port
                
                result.append({
                    "srcIp": src_ip,
                    "dstIp": dst_ip,
                    "protocol": protocol,
                    "port": srv_port,
                    "status": c.status,
                    "duration": "Active"
                })
                
                if len(result) >= limit:
                    break
                    
            return result
        except Exception as e:
            print(f"[ERROR] get_active_connections_list: {e}")
            return []
