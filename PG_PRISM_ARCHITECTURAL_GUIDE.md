# PG-Prism: Kapsamlı Mimari ve Protokol Kılavuzu

Bu döküman, **PG-Prism** projesinin çalışma felsefesini, PostgreSQL wire-protokolü seviyesindeki araya girme (interception) mantığını, Python ve Rust çekirdeklerindeki mimari tasarım kararlarını, karşılaşılan borrow checker engellerini ve çözümlerini kapsamlı bir şekilde açıklamaktadır. 

---

## 1. Felsefe ve Genel Mimari

### A. PG-Prism Nedir?
PG-Prism, PostgreSQL veritabanı ile istemciler (Örn: DBeaver, Go/Java/Python uygulamaları) arasına şeffaf bir şekilde yerleşen (transparent proxy), trafiği izleyen, manipüle eden (query rewriting) ve kural tabanlı olarak engelleyen bir **Database Proxy / Sidecar** yazılımıdır.

### B. Tasarım İlkeleri
1.  **Sıfır Dış Bağımlılık (Zero External Dependencies):** Python çekirdeği tamamen standart kütüphane (`asyncio`, `struct`, `ssl`, `re`) ile çalışır. Rust çekirdeği ise yalnızca temel asenkron ve YAML kütüphanelerini (`tokio`, `native-tls`, `serde`) kullanır.
2.  **Yüksek Performans ve Düşük Gecikme (Low Latency):** Özellikle Rust çekirdeğinde, her istemci bağlantısı ve sorgusu için sıfıra yakın bellek tahsisi (zero-allocation) hedeflenmiştir.
3.  **Çift Çekirdek Yapısı (Feature Parity):** Hem Python (kolay taşınabilirlik ve script esnekliği) hem de Rust (maksimum throughput ve kararlılık) motorları birebir aynı kuralları çalıştırır ve aynı protokol çıktılarını verir.

### C. Ağ ve Trafik Akışı

```text
[İstemci: DBeaver / App]
       │  (Port: 5434, TLS Şifreli)
       ▼
 ┌──────────┐
 │ HAProxy  │  --> SSL'i Passthrough modda iletir, PROXY v1 başlığı ekler
 └────┬─────┘
      │  (Port: 5433, PROXY v1 Başlığıyla Plaintext Soket)
      ▼
 ┌──────────────┐
 │   PG-Prism   │  --> PROXY başlığını okur, SSLRequest'i yakalar,
 │  (Sidecar)   │      SSL sonlandırır (TLS Termination), kuralları kontrol eder
 └────┬─────────┘
      │  (Port: 5432, Plaintext TCP, Enjekte Edilmiş application_name)
      ▼
 ┌──────────────┐
 │  PostgreSQL  │  --> Gerçek istemci IP'sini application_name'de loglar
 └──────────────┘
```

---

## 2. PostgreSQL Wire Protokolü Özellikleri

PostgreSQL 3.0 protokolü mesaj tabanlıdır. Her paket, 1 baytlık **Mesaj Tipi** (bazı başlangıç paketlerinde yoktur) ve 4 baytlık **Paket Uzunluğu** (uzunluk değerine bu 4 baytın kendisi de dahildir) ile başlar.

### A. Başlangıç Fazı (Startup Phase)
Bağlantı ilk kurulduğunda sunucu ve istemci şu paketleri sırasıyla işler:

#### 1. PROXY Protokol Başlığı (HAProxy v1)
HAProxy, istemcinin gerçek IP'sini kaybetmemek için TCP bağlantısının en başına şu düz metin satırı ekler:
```text
PROXY TCP4 [İstemci_IP] [HAProxy_IP] [İstemci_Port] [HAProxy_Port]\r\n
```
PG-Prism bu satırı satır sonu karakterine (`\r\n`) kadar okur ve içinden gerçek istemci IP'sini ayrıştırır.

#### 2. SSLRequest (`80877103`)
İstemci şifreli bağlanmak istiyorsa, ilk olarak 8 baytlık bir paket gönderir:
*   `[00 00 00 08]` (Paket Uzunluğu: 8 bayt)
*   `[04 d2 16 2f]` (SSLRequest Kodunun be-32 karşılığı: `80877103`)

**Proxy Yanıtı:**
*   Proxy SSL destekliyorsa tek baytlık `S` (ASCII `83`) döner ve hemen ardından soketi TLS el sıkışmasına (TLS Handshake) sokar.
*   SSL pasifse `N` (ASCII `78`) döner ve istemciyi plaintext bağlantıya zorlar.

#### 3. StartupMessage (`196608`)
TLS el sıkışması tamamlandıktan sonra (veya plaintext devam ediliyorsa doğrudan) istemci başlangıç parametrelerini gönderir:
*   `[4 byte]` (Toplam Uzunluk)
*   `[00 03 00 00]` (Protokol Versiyonu 3.0 be-32 karşılığı: `196608`)
*   `[Parametreler]` (Null-terminated anahtar-değer çiftleri, örn: `user\0postgres\0database\0postgres\0application_name\0dbeaver\0\0`)

### B. Sorgu Fazı (Query Phase)
Bağlantı kurulduktan sonra istemci iki farklı protokol kullanarak sorgu gönderebilir:

#### 1. Simple Query (`Q`)
İstemci tek bir paket içinde sorguyu düz metin olarak gönderir:
*   `b'Q'` (Mesaj tipi)
*   `[4 byte]` (Uzunluk)
*   `[Sorgu Metni + \0]` (Örn: `SELECT 1;\0`)

#### 2. Extended Query (Parse `P` / Bind `B` / Execute `E` / Sync `S`)
Sürücüler parametrik sorgularda Extended protokolü kullanır. PG-Prism sorguyu yakalamak için **Parse (`P`)** aşamasında araya girer:
*   `b'P'` (Mesaj tipi)
*   `[4 byte]` (Uzunluk)
*   `[Statement Adı + \0]` (Genelde boştur)
*   `[Sorgu Metni + \0]` (Örn: `SELECT * FROM secrets WHERE id = $1;\0`)
*   `[Parametre Tipleri vb.]`

---

## 3. Python Çekirdeği (Python Core) Tasarımı

Python çekirdeği, asenkron G/Ç işlemleri için `asyncio` kütüphanesini temel alır.

### A. SSL Sonlandırma Mantığı
Python'da plaintext soketi TLS soketine yükseltmek için `StreamWriter` sınıfının asenkron `start_tls` metodu kullanılır:

```python
# SSLRequest geldikten sonra istemciye 'S' gönderilir
client_writer.write(b'S')
await client_writer.drain()

# Soket TLS katmanına yükseltilir
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile=SSL_CERT_PATH, keyfile=SSL_KEY_PATH)

# start_tls asenkron olarak TLS handshake yapar ve soketi şeffaf şekilde günceller
await client_writer.start_tls(ssl_context)
```

### B. Bağımlılıksız YAML Ayrıştırıcı
Harici kütüphane kurmamak için `guardian.yaml` dosyasını satır satır okuyan basit bir YAML parse mantığı yazılmıştır. Girintileri (indentation) ve liste başlangıçlarını (`-`) takip ederek verileri Python sözlüklerine (`dict`) dönüştürür.

---

## 4. Rust Çekirdeği (Rust Core) Tasarımı

Rust çekirdeği, maksimum eşzamanlılık ve en düşük bellek ayak izi için `tokio` ve `native-tls` tabanlıdır.

### A. Dinamik SSL ve Boxed Async Stream
Rust'ta soketin TLS olup olmadığı derleme anında (compile-time) bilinmediği için, hem `TcpStream` hem de `TlsStream<TcpStream>` nesnelerini ortak bir çatı altında yönetmek gerekir. Bunu aşmak için dinamik trait nesnesi (`Box<dyn AsyncReadWrite>`) kullanılmıştır:

```rust
// AsyncRead + AsyncWrite + Unpin + Send trait'lerini tek bir isim altında topluyoruz
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

// İstemci akışı dinamik olarak atanır
let mut client_stream: Box<dyn AsyncReadWrite + Unpin + Send>;

if is_ssl {
    let tls_stream = acceptor.accept(raw_socket).await?;
    client_stream = Box::new(tls_stream);
} else {
    client_stream = Box::new(raw_socket);
}
```

### B. Borrow Checker Engelinin Aşılması: Soket Bölme (Split)
Rust'ta çift yönlü veri akışını (İstemciden Sunucuya ve Sunucudan İstemciye) asenkron olarak koşturmak için soketi okuma ve yazma kanallarına bölmek gerekir.

#### Sorun:
`tokio::io::split` kullanıldığında dönen `ReadHalf` and `WriteHalf` yapıları birbirine bağlıdır. Eğer `client_to_server` asenkron bloğu içinde bir sorgu engellendiğinde istemciye `ErrorResponse` yazmak için `WriteHalf`'ı mutably borrow edersek, aynı anda çalışan `server_to_client` (veritabanından gelen veriyi istemciye yazan blok) asenkron bloğu da `WriteHalf`'ı mutably borrow etmek isteyecektir. Bu durum derleme hatasına (`cannot borrow client_write_half as mutable more than once`) yol açar.

#### Çözüm:
`client_write_half` nesnesi bir `Arc<tokio::sync::Mutex>` ile sarılır. Böylece her iki asenkron blok da kendi lokal klonları üzerinden mutex kilidi alarak yazma kanalına güvenli ve çakışmasız erişim sağlar:

```rust
let (client_read_half, client_write_half) = tokio::io::split(client_stream);
let client_write_half = Arc::new(tokio::sync::Mutex::new(client_write_half));

// Veritabanından istemciye veri kopyalayan sunucu görevi
let client_write_half_clone = client_write_half.clone();
let server_to_client = async move {
    let mut buf = [0u8; 8192];
    loop {
        let n = pg_read_half.read(&mut buf).await?;
        if n == 0 { break; }
        let mut guard = client_write_half_clone.lock().await;
        guard.write_all(&buf[..n]).await?;
        guard.flush().await?;
    }
    Ok(())
};
```

---

## 5. Kritik Algoritmik Çözümler ve Hack'ler

### A. 63-Byte Kırpma (Application Name Truncation) Algoritması
PostgreSQL'in `application_name` sınırı 63 bayttır. Eğer istemci adı `DBeaver` ve istemci IP'si `192.168.1.50` ise, oluşturacağımız yeni değer `DBeaver - 192.168.1.50` olur.
Eğer orijinal ad çok uzunsa (Örn: `MyVeryLongCorporateApplicationNameThatIsTooLong`), IP adresini eklediğimizde sınır aşılır ve IP adresi kırpılır (Örn: `... - 192.168.1.5`).

#### Çözüm Algoritması (Python / Rust Ortak):
1.  `suffix = " - " + IP` uzunluğu hesaplanır (Örn: `192.168.1.50` için `3 + 12 = 15` bayt).
2.  Kullanılabilir alan: `available_len = 63 - suffix.len()`.
3.  Eğer `available_len <= 0` ise, doğrudan `suffix` değerinin ilk 63 karakteri kullanılır.
4.  Orijinal uygulama adı `available_len` boyutuna kırpılır ve sonuna `suffix` eklenir.

**Rust kodu:**
```rust
fn format_application_name(original_name: &str, app_ip: &str) -> String {
    let suffix = format!(" - {}", app_ip);
    let max_len = 63;
    if original_name.len() + suffix.len() <= max_len {
        return format!("{}{}", original_name, suffix);
    }
    let available_len = max_len.saturating_sub(suffix.len());
    if available_len == 0 {
        return suffix[..max_len].to_string();
    }
    let truncated_name = if original_name.len() > available_len {
        &original_name[..available_len]
    } else {
        original_name
    };
    format!("{}{}", truncated_name, suffix)
}
```

### B. Kesintisiz Hata Yönetimi (ErrorResponse + ReadyForQuery)
Sorgu güvenlik duvarına takıldığında soketi kapatmak yerine, istemciye veritabanı gibi davranıp hata döneriz.

#### 1. Hata Paketi Oluşturma (`make_error_response`)
PostgreSQL ErrorResponse paketi `E` tipiyle başlar. İçinde alan tanımlayıcıları (`S`: Önem Derecesi, `C`: SQLSTATE Kodu, `M`: Mesaj Metni) ve null sonlandırılmış string'ler barındırır. Paket çift null (`\0\0`) ile sonlandırılır.

```rust
fn make_error_response(message: &str, code: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"ERROR\0");
    body.push(b'C');
    body.extend_from_slice(code.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    body.push(0); // sonlandırma baytı
    
    let length = (body.len() + 4) as u32;
    let mut packet = Vec::new();
    packet.push(b'E');
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}
```

#### 2. Durum Resetleme (`ReadyForQuery`)
İstemciye hata iletildikten sonra, bağlantının kilitlenmesini engellemek için **ReadyForQuery (`Z`)** paketi gönderilir. Bu paket istemcinin durum makinesine veritabanının boşta (`I` - Idle) olduğunu bildirir:
```rust
// Z + [00 00 00 05] (uzunluk 5) + I (durum: Idle)
let ready_for_query = b"Z\x00\x00\x00\x05I";
```
Sorgu engelleme anında bu iki paket arka arkaya gönderilerek istemcinin sonraki sorguları göndermesi sağlanır.

---

## 6. Guardian YAML Kural Yapısı

Kurallar `guardian.yaml` dosyası içinde tanımlanır. Motor bu kuralları yukarıdan aşağıya (first-match-wins) tarar.

```yaml
rules:
  # 1. Kural: Belirli IP'den gelen postgres kullanıcısına tam yetki ver (Göz ardı et/Denetleme)
  - name: "Admin_Full_Access"
    action: "ALLOW"
    ips: ["127.0.0.1/32"]
    users: ["postgres"]

  # 2. Kural: Belirli bir kullanıcı grubunun tehlikeli sorgularını engelle
  - name: "Block_Dangerous_Queries"
    action: "INSPECT"
    ips: ["0.0.0.0/0"]
    users: ["app_user"]
    block_queries: ["DROP", "TRUNCATE"]
    block_tables: ["secrets", "billing_info"]
```

---

## 7. Derleme ve Çalıştırma Yönergeleri

### A. Docker Compose Ortamı
PG-Prism, `docker-compose.yml` dosyasında `CORE_TYPE` değişkenine göre (`rust` veya `python`) ayağa kalkar:

```yaml
  pg-prism:
    build: .
    container_name: pg-prism-sidecar
    environment:
      - PG_HOST=postgres
      - PG_PORT=5432
      - LISTEN_PORT=5433
      - CORE_TYPE=rust  # Veya 'python'
    ports:
      - "5433:5433"
    volumes:
      - ./core/rust/guardian.yaml:/app/guardian.yaml:ro
```

### B. HAProxy Entegrasyonu (`haproxy.cfg`)
HAProxy, istemci isteklerini TCP modunda karşılayarak `send-proxy` argümanıyla PG-Prism'e yönlendirir:

```text
frontend postgres_in
    bind *:5434
    mode tcp
    default_backend pg_prism_backend

backend pg_prism_backend
    mode tcp
    server pg_prism pg-prism:5433 send-proxy
```

---

## 8. Gelecekteki Yapay Zeka Modelleri İçin Notlar

> [!IMPORTANT]
> **PG-Prism Geliştirirken Dikkat Edilmesi Gereken Protokol Kuralları:**
> 1.  Soket veri aktarımlarında `struct.pack('!I', ...)` veya `.to_be_bytes()` (Big Endian) kullanılmalıdır.
> 2.  Sorgu filtrelemede `P` (Parse) paketi yakalandığında, sadece sorgu metni değiştirilmeli, parametre tiplerinin (`rest_of_payload`) yapısı bozulmamalıdır.
> 3.  Rust tarafında asenkron `tokio::io::copy` doğrudan `client_write_half` üzerinde kullanılamaz çünkü borrow checker engelinden ötürü yazma kanalı `MutexGuard` ile kilitlenmelidir. Kopyalama işlemi byte byte veya parça parça el ile yapılmalıdır.
