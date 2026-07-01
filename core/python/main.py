import asyncio
import struct
import logging
import os
import ssl

# --- AYARLAR ---
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 5433        # HAProxy trafiği buraya yönlendirecek
PG_HOST = os.environ.get('PG_HOST', 'localhost')     # Gerçek Postgres veya PgBouncer IP'si
PG_PORT = int(os.environ.get('PG_PORT', 5432))            # Gerçek Postgres veya PgBouncer Portu

# SSL Ayarları
SSL_ENABLED = os.environ.get('SSL_ENABLED', 'true').lower() in ('true', '1', 'yes')
SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', '/app/server.crt')
SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH', '/app/server.key')
# ---------------

SSL_CONTEXT = None

def generate_self_signed_cert():
    if not SSL_ENABLED:
        return
    if not os.path.exists(SSL_CERT_PATH) or not os.path.exists(SSL_KEY_PATH):
        logging.info("SSL sertifikası bulunamadı. Kendinden imzalı sertifika üretiliyor...")
        import subprocess
        try:
            os.makedirs(os.path.dirname(SSL_CERT_PATH), exist_ok=True)
            os.makedirs(os.path.dirname(SSL_KEY_PATH), exist_ok=True)
            subprocess.run([
                'openssl', 'req', '-new', '-newkey', 'rsa:2048', '-days', '365',
                '-nodes', '-x509', '-keyout', SSL_KEY_PATH, '-out', SSL_CERT_PATH,
                '-subj', '/CN=localhost'
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info("Kendinden imzalı SSL sertifikası başarıyla üretildi.")
        except Exception as e:
            logging.error(f"SSL sertifikası üretilirken hata oluştu: {e}")

def init_ssl_context():
    global SSL_CONTEXT
    if not SSL_ENABLED:
        logging.info("SSL devre dışı bırakıldı.")
        return
    
    generate_self_signed_cert()
    
    if os.path.exists(SSL_CERT_PATH) and os.path.exists(SSL_KEY_PATH):
        try:
            SSL_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            SSL_CONTEXT.load_cert_chain(certfile=SSL_CERT_PATH, keyfile=SSL_KEY_PATH)
            logging.info("SSL sertifikaları başarıyla yüklendi. SSL desteği aktif.")
        except Exception as e:
            logging.error(f"SSL context başlatılırken hata: {e}")
            SSL_CONTEXT = None
    else:
        logging.warning("SSL sertifikaları bulunamadığı için SSL desteği pasif.")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Server -> Client: Cevapları direkt ve hızlıca ilet
async def pipe_server_to_client(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass

# Client -> Server: İstekleri akıllıca süz (Smart Filter)
async def filter_client_to_server(reader, writer, app_ip):
    try:
        while True:
            # 1. Byte: Mesaj Tipi
            msg_type = await reader.read(1)
            if not msg_type:
                break
            
            # 4 Byte: Mesaj Uzunluğu
            try:
                len_bytes = await reader.readexactly(4)
            except asyncio.IncompleteReadError:
                break
            
            msg_len = struct.unpack('!I', len_bytes)[0]
            payload_len = msg_len - 4
            
            # OPTIMIZASYON: Akıllı Filtre
            # Sadece 'Q' (Query) veya 'P' (Parse) tipinde ve KÜÇÜK paketleri (1024 byte altı) incele.
            if (msg_type == b'Q' or msg_type == b'P') and payload_len < 1024:
                try:
                    payload = await reader.readexactly(payload_len)
                    
                    modified = False
                    new_payload = b''
                    
                    # --- Simple Query (Q) Handle ---
                    if msg_type == b'Q':
                        # Postgres protokolünde Query string \0 ile biter
                        if payload and payload[-1] == 0:
                            query_str = payload[:-1].decode('utf-8', errors='ignore')
                        else:
                            query_str = payload.decode('utf-8', errors='ignore')

                        if 'application_name' in query_str.lower() and 'set' in query_str.lower():
                            logging.info(f"SET komutu (Simple Query) yakalandı: {query_str.strip()}")
                            if "'" in query_str:
                                parts = query_str.split("'")
                                if len(parts) >= 3:
                                    old_name = parts[1]
                                    if app_ip not in old_name:
                                        new_name = f"{old_name} - {app_ip}"
                                        query_str = query_str.replace(f"'{old_name}'", f"'{new_name}'")
                                        logging.info(f"Sorgu rewrite edildi: {query_str.strip()}")
                                        modified = True
                        
                        if modified:
                            new_payload = query_str.encode('utf-8') + b'\0'
                    
                    # --- Extended Query Parse (P) Handle ---
                    elif msg_type == b'P':
                        # Format: [Statement Name \0] [Query String \0] [Param Types ...]
                        try:
                            # 1. Statement Name (Null terminated)
                            idx1 = payload.find(b'\0')
                            if idx1 != -1:
                                stmt_name = payload[:idx1] # Dahil değil \0
                                
                                # 2. Query String (Null terminated, idx1 + 1 den başlar)
                                idx2 = payload.find(b'\0', idx1 + 1)
                                if idx2 != -1:
                                    raw_query_bytes = payload[idx1+1:idx2]
                                    query_str = raw_query_bytes.decode('utf-8', errors='ignore')
                                    
                                    # Kalan kısım (Parametre tipleri vs.)
                                    rest_of_payload = payload[idx2+1:] # \0 dan sonrası
                                    
                                    if 'application_name' in query_str.lower() and 'set' in query_str.lower():
                                        logging.info(f"SET komutu (Parse) yakalandı: {query_str.strip()}")
                                        if "'" in query_str:
                                            parts = query_str.split("'")
                                            if len(parts) >= 3:
                                                old_name = parts[1]
                                                if app_ip not in old_name:
                                                    new_name = f"{old_name} - {app_ip}"
                                                    query_str = query_str.replace(f"'{old_name}'", f"'{new_name}'")
                                                    logging.info(f"Parse Query rewrite edildi: {query_str.strip()}")
                                                    modified = True
                                    
                                    if modified:
                                        # Paketi yeniden montajla: StmtName + \0 + NewQuery + \0 + Rest
                                        new_payload = stmt_name + b'\0' + query_str.encode('utf-8') + b'\0' + rest_of_payload
                        except Exception as e:
                            logging.error(f"Parse paketi işlenirken hata: {e}")
                            modified = False

                    # Gönderim Kararı
                    if modified:
                        new_len = len(new_payload) + 4
                        writer.write(msg_type)
                        writer.write(struct.pack('!I', new_len))
                        writer.write(new_payload)
                    else:
                        writer.write(msg_type)
                        writer.write(len_bytes)
                        writer.write(payload)

                except Exception as e:
                    logging.error(f"Paket inceleme hatası: {e}")
                    # Hata olursa orijinali gönder
                    writer.write(msg_type)
                    writer.write(len_bytes)
                    writer.write(payload)
            else:
                # Blind Forward
                writer.write(msg_type)
                writer.write(len_bytes)
                
                to_read = payload_len
                while to_read > 0:
                    chunk_size = min(to_read, 65536)
                    data = await reader.readexactly(chunk_size)
                    writer.write(data)
                    to_read -= chunk_size
            
            await writer.drain()

    except Exception:
        pass

async def handle_client(client_reader, client_writer):
    client_addr = client_writer.get_extra_info('peername')
    logging.info(f"Yeni bağlantı alındı: {client_addr}")
    pg_writer = None

    try:
        # 1. HAProxy'den gelen PROXY v1 Başlığını Oku
        proxy_line = await client_reader.readuntil(b'\r\n')
        if not proxy_line.startswith(b'PROXY'):
            logging.warning("PROXY başlığı bulunamadı, bağlantı reddedildi.")
            return

        # Gerçek İstemci IP'sini ayrıştır
        parts = proxy_line.decode('ascii').strip().split(' ')
        real_client_ip = parts[2]
        logging.info(f"Yakalanan Gerçek IP: {real_client_ip}")

        # Hedef Postgres'e bağlantı aç
        pg_reader, pg_writer = await asyncio.open_connection(PG_HOST, PG_PORT)

        # 2. Postgres Başlangıç Paketini Bekle ve Oku
        while True:
            try:
                length_bytes = await client_reader.readexactly(4)
            except asyncio.IncompleteReadError:
                logging.info("Client bağlantıyı kapattı (Length okunamadı).")
                return

            msg_length = struct.unpack('!I', length_bytes)[0]
            
            try:
                payload = await client_reader.readexactly(msg_length - 4)
            except asyncio.IncompleteReadError:
                logging.info("Client bağlantıyı kapattı (Payload okunamadı).")
                return

            if len(payload) >= 4:
                protocol = struct.unpack('!I', payload[:4])[0]

                # SSLRequest (80877103) kontrolü
                if protocol == 80877103:
                    if SSL_CONTEXT is not None:
                        logging.info("SSLRequest (80877103) alındı. 'S' gönderilerek SSL el sıkışması başlatılıyor.")
                        client_writer.write(b'S')
                        await client_writer.drain()
                        try:
                            await client_writer.start_tls(SSL_CONTEXT)
                            logging.info("Client ile SSL el sıkışması başarılı.")
                            continue
                        except Exception as ssl_err:
                            logging.error(f"Client SSL el sıkışma hatası: {ssl_err}")
                            return
                    else:
                        logging.info("SSLRequest (80877103) alındı. SSL pasif olduğundan 'N' gönderilerek reddediliyor.")
                        client_writer.write(b'N')
                        await client_writer.drain()
                        continue

                # GSSENCRequest (80877104) kontrolü
                if protocol == 80877104:
                    logging.info("GSSENCRequest (80877104) alındı. 'N' gönderilerek reddediliyor.")
                    client_writer.write(b'N')
                    await client_writer.drain()
                    continue

                # Startup Message (196608)
                if protocol == 196608:
                    logging.info(f"Startup Message yakalandı. IP enjekte ediliyor...")
                    try:
                        raw_params = payload[4:]
                        if raw_params and raw_params[-1] == 0:
                             raw_params = raw_params[:-1]
                        
                        params_list = raw_params.split(b'\0')
                        params_dict = {}
                        i = 0
                        while i < len(params_list) - 1:
                            key = params_list[i].decode('utf-8', errors='ignore')
                            val = params_list[i+1].decode('utf-8', errors='ignore')
                            params_dict[key] = val
                            i += 2
                        
                        if 'application_name' in params_dict:
                            current_app_name = params_dict['application_name']
                            new_app_name = f"{current_app_name} - {real_client_ip}"
                            logging.info(f"Mevcut uygulama adı güncelleniyor: {current_app_name} -> {new_app_name}")
                            params_dict['application_name'] = new_app_name
                        else:
                             logging.info(f"Uygulama adı bulunamadı, yeni ekleniyor: {real_client_ip}")
                             params_dict['application_name'] = real_client_ip
                        
                        new_params_bytes = b''
                        for k, v in params_dict.items():
                            new_params_bytes += k.encode('utf-8') + b'\0' + v.encode('utf-8') + b'\0'
                        
                        new_payload = payload[:4] + new_params_bytes + b'\0'
                        new_length = len(new_payload) + 4
                        new_packet = struct.pack('!I', new_length) + new_payload
                        
                        pg_writer.write(new_packet)
                        await pg_writer.drain()
                        
                    except Exception as e:
                        logging.error(f"Startup Message parse hatası: {e}")
                        pg_writer.write(length_bytes + payload)
                        await pg_writer.drain()
                        
                    break 
                else:
                    # Startup dışı paket -> olduğu gibi ilet
                    pg_writer.write(length_bytes + payload)
                    await pg_writer.drain()
                    break 
            else:
                pg_writer.write(length_bytes + payload)
                await pg_writer.drain()
                break

        # 3. İki Yönlü Trafik Başlat (Smart Filter active)
        try:
            task_s2c = asyncio.create_task(pipe_server_to_client(pg_reader, client_writer))
            await filter_client_to_server(client_reader, pg_writer, real_client_ip)
            task_s2c.cancel()
        except Exception as e:
             logging.error(f"Forwarding hatası: {e}")

    except Exception as e:
        logging.error(f"Bağlantı hatası: {e}")
    finally:
        logging.info("Bağlantı kapatılıyor.")
        client_writer.close()
        try:
            await client_writer.wait_closed()
        except: pass
            
        if pg_writer:
            pg_writer.close()
            try:
                await pg_writer.wait_closed()
            except: pass

async def main():
    init_ssl_context()
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    logging.info(f"Microproxy çalışıyor: {LISTEN_HOST}:{LISTEN_PORT}")
    logging.info(f"Trafik şuraya yönlendirilecek: {PG_HOST}:{PG_PORT}")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
