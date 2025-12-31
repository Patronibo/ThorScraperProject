# TOR Scraper

.onion sitelerini Tor ağı üzerinden tarayan ve istihbarat toplayan Go uygulaması.

## 🎯 Proje Amacı

Siber tehdit aktörleri izlerini kaybettirmek için Tor ağını kullanmaktadır. Bu araç, yüzlerce .onion adresini (sızıntı siteleri, forumlar, marketler) otomatik olarak tarayarak CTI (Cyber Threat Intelligence) süreçlerindeki "Collection" ve "Automation" yetkinliklerini destekler.

## 📋 Özellikler

- **Tor Proxy Entegrasyonu**: SOCKS5 proxy (127.0.0.1:9050/9150) üzerinden anonim trafik
- **IP Sızıntısı Önleme**: Özel `http.Transport` ve `http.Client` yapılandırması
- **Hata Toleransı**: Kapanmış siteler programı durdurmaz, loglayıp devam eder
- **Web Archive Tarzı Metadata**: Title, description, server, headers, cookies
- **Link Çıkarma**: Internal, external ve .onion linkleri kategorize eder
- **Tor Doğrulama**: check.torproject.org ile Tor IP kontrolü ve kayıt
- **JSON Rapor**: Tüm verileri `report.json` dosyasına yazar
- **Screenshot**: Tor üzerinden chromedp ile tam sayfa ekran görüntüsü
- **İnteraktif Menü**: Hangi siteyi taramak istediğinizi seçebilirsiniz

## 📁 Proje Yapısı

```
TOR-Scraper/
├── main.go              # Ana uygulama (tek dosya)
├── go.mod               # Go modülü
├── go.sum               # Bağımlılıklar
├── targets.yaml         # Hedef .onion listesi (isim | url formatı)
├── scan_report.log      # Aktif/Pasif durum raporu
├── README.md            # Bu dosya
└── outputs/
    ├── html/            # Kaydedilen HTML dosyaları
    ├── screenshots/     # Ekran görüntüleri (PNG)
    └── report.json      # JSON rapor (metadata + linkler)
```

## 🔧 Gereksinimler

- **Go**: 1.21 veya üzeri
- **Tor Service**: Arka planda çalışır durumda (port 9050 veya 9150)
- **Google Chrome/Chromium**: Screenshot için gerekli (chromedp kullanılıyor)

### Tor Kurulumu

**Windows (Tor Browser):**
```
Tor Browser'ı indirip çalıştırın. Port: 9150
```

**Linux:**
```bash
sudo apt install tor
sudo systemctl start tor
# Port: 9050
```

## 🚀 Kurulum ve Çalıştırma

```bash
# Projeyi klonla
git clone <repo-url>
cd TOR-Scraper

# Bağımlılıkları yükle
go mod tidy

# Hedef dosyasını düzenle
nano targets.yaml

# Çalıştır
go run main.go
```

## 📝 targets.yaml Formatı

```yaml
# TOR Scraper - Hedef Listesi
# Format: isim | url

GhostHub Forum | http://example1234567890.onion
DarkZone Market | http://anothersite5678.onion
AskQuery Forum | http://thirdsite9999.onion

# Sadece URL de yazabilirsiniz:
http://anotherurl.onion
```

## 🎯 İnteraktif Site Seçimi

Program çalıştırıldığında size bir menü gösterir:

```
╔══════════════════════════════════════════════════════════════╗
║                    TOR SCRAPER - HEDEF SEÇİMİ                ║
╠══════════════════════════════════════════════════════════════╣
║  [1] GhostHub Forum                                          ║
║  [2] DarkZone Market                                         ║
║  [3] AskQuery Forum                                          ║
╠══════════════════════════════════════════════════════════════╣
║  [0] Tüm siteleri tara                                       ║
║  [q] Çıkış                                                   ║
╚══════════════════════════════════════════════════════════════╝

Seçiminiz (örn: 1,2,3 veya 0 hepsi için): 
```

- **Tek site**: `1` yazıp Enter
- **Birden fazla site**: `1,2,3` yazıp Enter  
- **Tüm siteler**: `0` yazıp Enter
- **Çıkış**: `q` yazıp Enter

## 📊 Çıktılar

### 1. Konsol Çıktısı

```
=== TOR Scraper Başlatılıyor ===
[INFO] Tor proxy bulundu: 127.0.0.1:9150
[INFO] Tor modu aktif
[SUCCESS] Tor bağlantısı aktif! IP: 193.26.115.82
[INFO] 5 adet URL bulundu, tarama başlatılıyor...
[INFO] [1/5] Scanning: http://example.onion
[SUCCESS] http://example.onion -> Title: Example Site | Links: 45
[ERR] http://deadsite.onion -> Bağlantı hatası: timeout
...
=== Tarama Tamamlandı ===
[SUMMARY] Toplam: 5 | Aktif: 3 | Pasif: 2
```

### 2. scan_report.log

```
=== TOR SCRAPER SCAN REPORT ===
Tarih: 2025-12-30 21:07:51

[ACTIVE] http://example.onion
    -> HTML: example_20251230_210751.html
    -> Title: Example Site
    -> Links: 45 total (10 internal, 5 external, 30 onion)

[PASSIVE] http://deadsite.onion
    -> Hata: Bağlantı hatası: timeout

=== ÖZET ===
Toplam: 5 | Aktif: 3 | Pasif: 2
```

### 3. report.json

```json
{
  "run_id": "1767118066",
  "started_at": "2025-12-30T18:07:46Z",
  "finished_at": "2025-12-30T18:07:51Z",
  
  "tor_connection": {
    "connected": true,
    "tor_ip": "193.26.115.82",
    "proxy_used": "127.0.0.1:9150",
    "verified_at": "2025-12-30T18:07:46Z",
    "verify_url": "https://check.torproject.org/api/ip"
  },
  
  "summary": {
    "total_urls": 1,
    "active_urls": 1,
    "passive_urls": 0
  },
  
  "results": [
    {
      "url": "http://example.onion",
      "status": "active",
      "status_code": 200,
      "response_time_ms": 2704,
      "scanned_at": "2025-12-30T18:07:48Z",
      "title": "Example Site",
      "meta_description": "Site description",
      "server": "Apache",
      "content_type": "text/html; charset=UTF-8",
      "content_length": 37084,
      "headers": {
        "Server": "Apache",
        "Content-Type": "text/html; charset=UTF-8",
        "Set-Cookie": "session=abc123; HttpOnly"
      },
      "cookies": [
        {
          "name": "session",
          "value": "abc123",
          "http_only": true
        }
      ],
      "links": {
        "total_count": 121,
        "internal_links": [...],
        "external_links": [...],
        "onion_links": [
          {"url": "http://another.onion", "text": "Another Site"},
          {"url": "http://market.onion", "text": "Dark Market"}
        ]
      },
      "html_file": "example_20251230_210751.html"
    }
  ]
}
```

## 🏗️ Mimari (4 Ana Modül)

### 1. Dosya Okuma Modülü (Input Handler)
- `targets.yaml` dosyasını okur
- Satır sonu karakterlerini temizler (whitespace trimming)
- Boş satır ve yorum satırlarını atlar

### 2. Tor Proxy Yönetimi (Go Proxy Client)
- `golang.org/x/net/proxy` ile SOCKS5 bağlantısı
- Önce 9050, sonra 9150 portunu dener
- IP sızıntısını önlemek için özel `http.Transport`

### 3. İstek ve Hata Yönetimi
- Kapanmış siteler programı durdurmaz
- Hata loglanır, bir sonraki URL'e geçilir
- Timeout ve connection hataları handle edilir

### 4. Veri Kayıt (Output Writer)
- HTML dosyaları: `outputs/html/`
- JSON rapor: `outputs/report.json`
- Log rapor: `scan_report.log`

## 📦 Kullanılan Kütüphaneler

| Kütüphane | Açıklama |
|-----------|----------|
| `net/http` | HTTP istekleri |
| `golang.org/x/net/proxy` | SOCKS5 proxy desteği |
| `golang.org/x/net/html` | HTML parsing ve link çıkarma |
| `os`, `bufio` | Dosya okuma/yazma |
| `encoding/json` | JSON rapor oluşturma |

## 🔒 OpSec (Operasyonel Güvenlik)

- **User-Agent**: Tarayıcı gibi görünmek için Chrome UA kullanılır
- **Headers**: Accept, Accept-Language, Accept-Encoding
- **Tor Doğrulama**: check.torproject.org ile IP kontrolü
- **IP Sızıntısı Önleme**: Tüm trafik SOCKS5 üzerinden

## ⚠️ Yasal Uyarı

Bu araç **yalnızca yasal ve etik amaçlarla** kullanılmalıdır:
- Siber güvenlik araştırmaları
- Akademik çalışmalar
- CTI (Cyber Threat Intelligence) operasyonları
- İzinli penetrasyon testleri

Yasadışı faaliyetlerde kullanılması kesinlikle yasaktır.

## 📈 Değerlendirme Kriterleri

| Kriter | Puan | Açıklama |
|--------|------|----------|
| Girdi Dosyası Okuma | 15 | URL listesi hatasız okunur |
| Tor Proxy Yönetimi | 15 | SOCKS5 üzerinden trafik yönlendirme |
| Hata Yönetimi | 15 | Panic olmadan devam etme |
| Kod Kalitesi | 15 | Go idioms, hata kontrolü |
| Raporlama | 15 | Konsol + dosya loglama |
| User-Agent/OpSec | 10 | Tarayıcı gibi görünme |
| Proje Raporu | 15 | Profesyonel dokümantasyon |

## 📸 Örnek Ekran Görüntüleri

### Tarama Süreci
```
2025/12/30 21:07:46 === TOR Scraper Başlatılıyor ===
2025/12/30 21:07:46 [INFO] Tor proxy bulundu: 127.0.0.1:9150
2025/12/30 21:07:46 [INFO] Tor modu aktif
2025/12/30 21:07:48 [SUCCESS] Tor bağlantısı aktif! IP: 193.26.115.82
2025/12/30 21:07:48 [INFO] 1 adet URL bulundu, tarama başlatılıyor...
2025/12/30 21:07:48 [INFO] [1/1] Scanning: http://example.onion
2025/12/30 21:07:51 [SUCCESS] http://example.onion -> Title: Example | Links: 121
2025/12/30 21:07:51 === Tarama Tamamlandı ===
2025/12/30 21:07:51 [SUMMARY] Toplam: 1 | Aktif: 1 | Pasif: 0
```

## 👤 Geliştirici

CTI Automation Project - Go ile Tor Scraper

## 📄 Lisans

Bu proje eğitim amaçlıdır.
