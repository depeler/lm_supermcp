# Değişiklik Geçmişi

Tüm önemli değişiklikler burada belgelenmiştir.

## [3.0] - 2026-08-13

### Güvenlik İyileştirmeleri 🛡️
- **Rate Limiting**: Thread-safe `RateLimiter` ile tüm araçlarda dakikada max 30 istek kısıtlaması
- **URL Doğrulama**: Tehlikeli şemalar (`file://`, `javascript:`, `ftp://`) ve özel ağ erişimleri engellendi
- **JavaScript Güvenliği**: `eval()`, `fetch()`, `document.*` gibi tehlikeli kalıplar bloklandı
- **PDF Güvenliği**: Content-Type doğrulama ve 10 MB dosya boyutu limiti eklendi

### Merkezi Yapılandırma 🔧
- Tüm güvenlik eşikleri tek bir `SECURITY_CONFIG` sözlüğünde toplanır

---

## [2.0] - 2026-08-13

### Performans İyileştirmeleri ⚡
- **Paralel İşleme**: `ThreadPoolExecutor` ile çoklu sayfa okuma hızı %300-500 arttı
- **Tarih Enjeksiyonu**: Tool açıklamalarına dinamik tarih eklendi (model otomatik bugünü bilir)

### Özellik Eklentileri 🎯
- **PDF Desteği**: Uzak PDF dosyalarını okuma ve metin çıkarma
- **ddgs Kütüphanesi**: Rate-limit sorunları için güncel arama motoru paketi

---

## [1.0] - İlk Sürüm

İlk sürüm ile temel araçlar eklendi:
- `search_web` - İnternet araması ve otomatik sayfa okuma
- `read_webpage` - Tek sayfa içeriği çıkarma
- `execute_javascript` - Güvenli JavaScript çalışma