import asyncio
import socket
import struct
import time
import os
import hashlib
import statistics
import hmac
import base64

# Configuration
CONCURRENCY = 50        # Number of simultaneous connections
DURATION = 5            # Seconds to run per iteration
ITERATIONS = 10         # Number of times to repeat the test per port
PG_USER = "postgres"
PG_PASS = "test123"
PG_DB = "postgres"

# PostgreSQL Protocol Constants
PROTOCOL_VERSION = 196608
SSL_REQUEST = 80877103
CANCEL_REQUEST = 80877102

def fail(msg):
    raise Exception(msg)

class MinimalPGClient:
    def __init__(self, host, port, user, password, db, use_proxy_header=False):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.db = db
        self.use_proxy_header = use_proxy_header
        self.reader = None
        self.writer = None

    async def connect(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            
            # Send PROXY Header if required (Mocking HAProxy)
            if self.use_proxy_header:
                # PROXY TCP4 SOURCE_IP DEST_IP SOURCE_PORT DEST_PORT\r\n
                proxy_line = f"PROXY TCP4 192.168.1.50 127.0.0.1 12345 {self.port}\r\n"
                self.writer.write(proxy_line.encode('ascii'))
                await self.writer.drain()
            
            # Send Startup Message
            params = {
                'user': self.user,
                'database': self.db,
                'application_name': 'benchmark_client'
            }
            
            payload = bytearray()
            for k, v in params.items():
                payload.extend(k.encode('utf-8') + b'\0')
                payload.extend(v.encode('utf-8') + b'\0')
            payload.append(0)
            
            length = len(payload) + 8
            msg = struct.pack('!I', length) + struct.pack('!I', PROTOCOL_VERSION) + payload
            self.writer.write(msg)
            await self.writer.drain()
            
            # Handle Auth
            while True:
                msg_type = await self.reader.readexactly(1)
                length_bytes = await self.reader.readexactly(4)
                length = struct.unpack('!I', length_bytes)[0]
                payload = await self.reader.readexactly(length - 4)
                
                # print(f"Msg: {msg_type} len={length}")

                if msg_type == b'R': # Authentication
                    auth_type = struct.unpack('!I', payload[:4])[0]
                    # print(f"Auth Type: {auth_type}")

                    if auth_type == 0: # Ok
                        pass
                    elif auth_type == 3: # Cleartext Password
                        password_packet = self.password.encode('utf-8') + b'\0'
                        resp_len = len(password_packet) + 4
                        self.writer.write(b'p' + struct.pack('!I', resp_len) + password_packet)
                        await self.writer.drain()
                    elif auth_type == 5: # MD5 Password
                        salt = payload[4:8]
                        m1 = hashlib.md5(self.password.encode('utf-8') + self.user.encode('utf-8')).hexdigest()
                        m2 = hashlib.md5(m1.encode('utf-8') + salt).hexdigest()
                        response = 'md5' + m2
                        password_packet = response.encode('utf-8') + b'\0'
                        resp_len = len(password_packet) + 4
                        self.writer.write(b'p' + struct.pack('!I', resp_len) + password_packet)
                        await self.writer.drain()
                    elif auth_type == 10: # SASL
                        mechanisms = payload[4:].split(b'\0')
                        if b'SCRAM-SHA-256' not in mechanisms:
                            fail(f"Server does not support SCRAM-SHA-256: {mechanisms}")

                        client_nonce = base64.b64encode(os.urandom(24)).decode('ascii')
                        client_first_message_bare = f"n={self.user},r={client_nonce}"
                        gs2_header = "n,," 
                        client_initial_message = gs2_header + client_first_message_bare
                        
                        mech_name = b'SCRAM-SHA-256\0'
                        initial_msg_bytes = client_initial_message.encode('utf-8')
                        
                        packet_len = 4 + len(mech_name) + 4 + len(initial_msg_bytes)
                        packet = b'p' + struct.pack('!I', packet_len) + mech_name + struct.pack('!I', len(initial_msg_bytes)) + initial_msg_bytes
                        self.writer.write(packet)
                        await self.writer.drain()
                        
                        self.client_first_message_bare = client_first_message_bare
                        self.client_nonce = client_nonce

                    elif auth_type == 11: # SASL Continue
                        server_msg = payload[4:].decode('utf-8')
                        # print(f"Server SASL Continue: {server_msg}")
                        params = dict(item.split('=', 1) for item in server_msg.split(','))
                        
                        r_server = params['r']
                        s_salt_b64 = params['s']
                        i_iter = int(params['i'])
                        
                        if not r_server.startswith(self.client_nonce):
                            fail("Server nonce does not match client nonce")

                        salt = base64.b64decode(s_salt_b64)
                        
                        salted_password = hashlib.pbkdf2_hmac('sha256', self.password.encode('utf-8'), salt, i_iter)
                        client_key = hmac.new(salted_password, b"Client Key", hashlib.sha256).digest()
                        stored_key = hashlib.sha256(client_key).digest()
                        
                        client_final_message_without_proof = f"c=biws,r={r_server}"
                        auth_message = f"{self.client_first_message_bare},{server_msg},{client_final_message_without_proof}"
                        
                        client_signature = hmac.new(stored_key, auth_message.encode('utf-8'), hashlib.sha256).digest()
                        client_proof = bytes(x ^ y for x, y in zip(client_key, client_signature))
                        proof_b64 = base64.b64encode(client_proof).decode('ascii')
                        
                        client_final_message = f"{client_final_message_without_proof},p={proof_b64}"
                        cf_bytes = client_final_message.encode('utf-8')
                        
                        packet_len = 4 + len(cf_bytes)
                        packet = b'p' + struct.pack('!I', packet_len) + cf_bytes
                        self.writer.write(packet)
                        await self.writer.drain()
                        
                    elif auth_type == 12: # SASL Final
                        # print("SASL Final received")
                        pass
                    else:
                        raise Exception(f"Unsupported Auth Type: {auth_type}")
                
                elif msg_type == b'Z': # ReadyForQuery
                    break
                elif msg_type == b'E': # Error
                    err_msg = payload.decode('utf-8', errors='ignore')
                    raise Exception(f"PG Error: {err_msg}")
                elif msg_type == b'K': # BackendKeyData
                    pass
                elif msg_type == b'S': # ParameterStatus
                    pass
                    
        except Exception as e:
            # print(f"Connection failed: {e}")
            raise

    async def query_simple(self, sql):
        # Send Query
        query_bytes = sql.encode('utf-8') + b'\0'
        length = len(query_bytes) + 4
        self.writer.write(b'Q' + struct.pack('!I', length) + query_bytes)
        await self.writer.drain()
        
        # Read until ReadyForQuery
        while True:
            try:
                msg_type = await self.reader.readexactly(1)
                len_bytes = await self.reader.readexactly(4)
                length = struct.unpack('!I', len_bytes)[0]
                payload = await self.reader.readexactly(length - 4)
                
                if msg_type == b'Z':
                    break
                elif msg_type == b'E':
                     raise Exception(f"Query Error: {payload}")
                     
            except asyncio.IncompleteReadError:
                raise Exception("Connection closed unexpectedly")

    async def close(self):
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except:
                pass

async def benchmark_worker(host, port, duration, stats, use_proxy_header):
    client = MinimalPGClient(host, port, PG_USER, PG_PASS, PG_DB, use_proxy_header)
    try:
        await client.connect()
        
        end_time = time.time() + duration
        count = 0
        
        while time.time() < end_time:
            t0 = time.time()
            await client.query_simple("SELECT 1")
            t1 = time.time()
            stats.append(t1 - t0)
            count += 1
            
        await client.close()
        return count
    except Exception as e:
        print(f"Worker error on port {port}: {e}")
        return 0

async def run_iteration(port):
    stats = [] # Store latencies
    tasks = []
    
    # Pre-warm / Connect
    # Real-world benchmark: we want to measure throughput of established connections usually,
    # or connection establishment. Here we measure QUERY throughput on persistent connections.
    
    use_proxy = (port == 5002) # Only Rust core (or Python core) behind HAProxy would need this
    
    clients = []
    for _ in range(CONCURRENCY):
        clients.append(benchmark_worker("127.0.0.1", port, DURATION, stats, use_proxy))
        
    start_time = time.time()
    results = await asyncio.gather(*clients)
    total_time = time.time() - start_time
    
    total_queries = sum(results)
    tps = total_queries / total_time if total_time > 0 else 0
    
    return tps, stats

async def main():
    ports = [5432, 5002]
    results_db = {p: {'tps': [], 'latencies': []} for p in ports}
    
    print(f"{'='*60}")
    print(f"Professional Benchmark v1.0")
    print(f"Goal: Compare Direct (5432) vs Rust Proxy (5001)")
    print(f"Config: {CONCURRENCY} concurrent clients, {ITERATIONS} iterations of {DURATION}s each.")
    print(f"{'='*60}\n")

    for i in range(ITERATIONS):
        print(f"--- Iteration {i+1}/{ITERATIONS} ---")
        for port in ports:
            print(f"Benchmarking Port {port}...", end='', flush=True)
            try:
                tps, latencies = await run_iteration(port)
                results_db[port]['tps'].append(tps)
                results_db[port]['latencies'].extend(latencies)
                print(f" Done. TPS: {tps:.2f}")
            except Exception as e:
                print(f" FAIL: {e}")
        print("")
        time.sleep(1) # Cooldown

    print(f"\n{'='*60}")
    print(f"{'PORT':<10} {'AVG TPS':<15} {'MIN TPS':<15} {'MAX TPS':<15} {'AVG LATENCY (ms)':<20}")
    print(f"{'-'*75}")
    
    baseline_tps = 0
    
    for port in ports:
        tps_list = results_db[port]['tps']
        lat_list = results_db[port]['latencies']
        
        if not tps_list:
            continue
            
        avg_tps = statistics.mean(tps_list)
        min_tps = min(tps_list)
        max_tps = max(tps_list)
        
        avg_lat = (statistics.mean(lat_list) * 1000) if lat_list else 0
        
        if port == 5432:
            baseline_tps = avg_tps
            
        print(f"{port:<10} {avg_tps:<15.2f} {min_tps:<15.2f} {max_tps:<15.2f} {avg_lat:<20.4f}")

    print(f"{'='*60}")
    
    rust_tps = statistics.mean(results_db[5002]['tps'])
    if baseline_tps > 0:
        ratio = (rust_tps / baseline_tps) * 100
        print(f"\nCONCLUSION:")
        print(f"Rust Core Performance: {ratio:.2f}% of Direct PostgreSQL")
        overhead = ((baseline_tps - rust_tps) / baseline_tps) * 100
        print(f"Proxy Overhead: {overhead:.2f}%")

if __name__ == "__main__":
    # Suppress asyncio logging
    # logging.getLogger('asyncio').setLevel(logging.CRITICAL)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
