import socket
import threading
import time
import struct
import re
import requests
import json
import os
import sys
from dotenv import load_dotenv
from google.cloud import compute_v1

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["TERM"] = "xterm-256color"

load_dotenv()

class Col:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

PROJECT = os.getenv("PROJECT_ID")
ZONE = os.getenv("ZONE")
INSTANCE = os.getenv("INSTANCE_NAME")
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
DNS_RECORD_NAME = os.getenv("DNS_RECORD_NAME")
ORCHESTRATOR_IP = os.getenv("ORCHESTRATOR_IP")
RCON_HOST = os.getenv("RCON_HOST")
RCON_PORT = int(os.getenv("RCON_PORT", 25575))
RCON_PASSWORD = os.getenv("RCON_PASSWORD")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 25565))
IDLE_SHUTDOWN_SECONDS = int(os.getenv("IDLE_SHUTDOWN_SECONDS", 900))

def log(msg, level="INFO"):
    timestamp = time.strftime('%H:%M:%S')
    prefix = f"[{Col.BLUE}{timestamp}{Col.END}]"
    if level == "INFO": icon = f"{Col.CYAN}ℹ{Col.END}"
    elif level == "SUCCESS": icon = f"{Col.GREEN}✔{Col.END}"
    elif level == "WARN": icon = f"{Col.YELLOW}⚠{Col.END}"
    elif level == "ERROR": icon = f"{Col.RED}✖{Col.END}"
    elif level == "WAKE": icon = f"{Col.MAGENTA}⚡{Col.END}"
    print(f"{prefix} {icon} {msg}", flush=True)

def read_varint(sock):
    d = 0
    for i in range(5):
        try:
            b = sock.recv(1)
            if not b: return None
            b = ord(b)
            d |= (b & 0x7F) << (7 * i)
            if not (b & 0x80): break
        except: return None
    return d

def encode_varint(d):
    o = b''
    while True:
        b = d & 0x7F
        d >>= 7
        if d != 0: o += struct.pack('B', b | 0x80)
        else: o += struct.pack('B', b); break
    return o

def create_packet(packet_id, data):
    payload = encode_varint(packet_id) + data
    return encode_varint(len(payload)) + payload

def update_dns(new_ip, destination_name):
    if not new_ip or new_ip == "0.0.0.0": return
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    try:
        url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records?name={DNS_RECORD_NAME}"
        res = requests.get(url, headers=headers).json()
        if not res['result']: return
        record = res['result'][0]
        record_id = record['id']
        current_cf_ip = record['content']
        if current_cf_ip == new_ip: return 
        data = {"type": "A", "name": DNS_RECORD_NAME, "content": new_ip, "ttl": 60, "proxied": False}
        requests.put(f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}", headers=headers, json=data)
        log(f"DNS Aligned to {Col.BOLD}{destination_name}{Col.END} ({Col.GREEN}{new_ip}{Col.END})", "SUCCESS")
    except Exception as e: log(f"DNS Error: {e}", "ERROR")

def send_rcon(host, port, password, command):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        sock.connect((host, port))
        def pkt(t, b):
            d = struct.pack('<ii', 123, t) + b.encode('utf-8') + b'\x00\x00'
            sock.sendall(struct.pack('<i', len(d)) + d)
            l_raw = sock.recv(4)
            if not l_raw: return ""
            l = struct.unpack('<i', l_raw)[0]
            return sock.recv(l)[8:-2].decode('utf-8', errors='ignore')
        pkt(3, password); r = pkt(2, command); sock.close()
        return r
    except: raise

compute = compute_v1.InstancesClient()
last_activity = time.time()

def get_vm_status():
    try:
        req = compute_v1.GetInstanceRequest(project=PROJECT, zone=ZONE, instance=INSTANCE)
        inst = compute.get(request=req)
        ip = inst.network_interfaces[0].access_configs[0].nat_i_p if inst.network_interfaces[0].access_configs else None
        return inst.status, ip
    except: return "UNKNOWN", None

def handle_client(conn, addr):
    try:
        conn.settimeout(2.0)
        length = read_varint(conn)
        if length is None: return
        packet_id = read_varint(conn)
        if packet_id != 0: return
        protocol_version = read_varint(conn)
        addr_len = read_varint(conn)
        conn.recv(addr_len)
        conn.recv(2)
        next_state = read_varint(conn)
        if next_state == 1:
            status, _ = get_vm_status()
            if status in ["PROVISIONING", "STAGING"]:
                motd, ver_name = "§6● §fStatus: §lBOOTING VM...", "§6Booting..."
            elif status == "RUNNING":
                try:
                    send_rcon(RCON_HOST, RCON_PORT, RCON_PASSWORD, "list")
                    motd = "§d● §fStatus: §lServer instance is ready... waiting for DNS"
                    ver_name = "§dFinalizing..."
                except:
                    motd = "§e● §fStatus: §lSTARTING SERVER INSTANCE..."
                    ver_name = "§eStarting..."
            else:
                motd, ver_name = "§a● §fGateway §7| §eJoin to Wake", "§aOnline"
            response_json = {"version": {"name": ver_name, "protocol": protocol_version}, "players": {"max": 1, "online": 0}, "description": {"text": motd}}
            json_payload = json.dumps(response_json).encode('utf-8')
            conn.recv(1024) 
            conn.sendall(create_packet(0x00, encode_varint(len(json_payload)) + json_payload))
        elif next_state == 2:
            status, _ = get_vm_status()
            if status != "RUNNING":
                log(f"Connection from {Col.YELLOW}{addr[0]}{Col.END} triggered {Col.MAGENTA}Power On{Col.END}", "WAKE")
                compute.start(project=PROJECT, zone=ZONE, instance=INSTANCE)
                global last_activity
                last_activity = time.time()
                msg = "§6§lGateway\n\n§fServer is booting. Please wait."
            else:
                msg = "§b§lStarting Server Instance...\n\n§fPlease refresh server list in a few minute."
            msg_json = json.dumps({"text": msg}).encode('utf-8')
            packet = b'\x00' + encode_varint(len(msg_json)) + msg_json
            conn.sendall(encode_varint(len(packet)) + packet)
            time.sleep(0.3)
    except: pass
    finally:
        try: conn.close()
        except: pass

def monitor_loop():
    global last_activity
    while True:
        status, game_ip = get_vm_status()
        if status == "RUNNING" and game_ip:
            try:
                res = send_rcon(RCON_HOST, RCON_PORT, RCON_PASSWORD, "list")
                update_dns(game_ip, "server")
                match = re.search(r'There are (\d+)', res)
                if match and int(match.group(1)) > 0:
                    last_activity = time.time()
                elif (time.time() - last_activity) > IDLE_SHUTDOWN_SECONDS:
                    log("Idle timeout reached. Initiating shutdown.", "WARN")
                    send_rcon(RCON_HOST, RCON_PORT, RCON_PASSWORD, "stop")
                    time.sleep(5)
                    compute.stop(project=PROJECT, zone=ZONE, instance=INSTANCE)
                    update_dns(ORCHESTRATOR_IP, "orchestrator")
            except:
                last_activity = time.time() 
        elif status == "TERMINATED" or status == "UNKNOWN":
            update_dns(ORCHESTRATOR_IP, "orchestrator")
        time.sleep(10 if status == "RUNNING" else 45)

if __name__ == "__main__":
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{Col.BOLD}{Col.CYAN}=========================================={Col.END}")
    log(f"Project: {Col.YELLOW}{PROJECT}{Col.END}")
    log(f"Instance: {Col.YELLOW}{INSTANCE}{Col.END}")
    log(f"DNS: {Col.YELLOW}{DNS_RECORD_NAME}{Col.END}")
    print(f"{Col.CYAN}------------------------------------------{Col.END}")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("0.0.0.0", LISTEN_PORT))
        listener.listen(64)
        log(f"Socket listening on port {Col.BOLD}{LISTEN_PORT}{Col.END}", "SUCCESS")
    except Exception as e:
        log(f"Failed to bind port: {e}", "ERROR")
        exit(1)
    threading.Thread(target=monitor_loop, daemon=True).start()
    while True:
        try:
            c, a = listener.accept()
            threading.Thread(target=handle_client, args=(c, a), daemon=True).start()
        except: continue
