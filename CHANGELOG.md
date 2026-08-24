# Değişiklik Geçmişi

Tüm önemli değişiklikler burada belgelenmiştir.

## [3.4] - 2026-08-24

### Çok Boyutlu Derin Web Araştırması ve Akıl Yürütme Motoru (SQLite Destekli) 🧠🔬
- **`deep_research` MCP Aracı**: Verilen herhangi bir konuyu genel tanım, avantajlar, dezavantajlar/riskler, alternatiflerle karşılaştırmalar ve gelecek trendleri olarak çoklu boyutlara ayırıp eş zamanlı derinlemesine araştıran araç eklendi.
- **Geçici SQLite Araştırma Belleği (`ResearchSessionDB`)**: Araştırma esnasında toplanan kaynakları tekilleştiren, alıntı ve bulguları perspektiflerine göre ilişkisel olarak SQLite'ta (`:memory:`) saklayıp organize eden mimari kuruldu.
- **Karşılaştırma Matrisi ve Akıl Yürütme Çıktısı**: Ham arama sonuçlarını sadece listelemek yerine; fikir birliği (consensus), çelişen görüşler ve alternatiflerle doğrudan karşılaştırma matrisini sentezleyen zengin rapor formatı eklendi.

---

## [3.3] - 2026-08-21

### Dinamik Tarih ve Zaman Bildirimi 🕒
- **Otomatik Zaman Enjeksiyonu (`_get_datetime_header`)**: Tüm MCP araçlarının dönüşlerinin en başına güncel yerel tarih/saat, gün adı ve UTC zaman bilgisi eklendi. LLM her araç çalıştığında ek bir sorgu yapmaya gerek kalmadan kesin güncel zamanı öğrenir.
- **Fiyat Arama Tablo Formatı**: `search_prices` sonuçları her zaman standart Markdown tablosu ve 'Satın Alma Linki' sütunu ile sunulacak şekilde standartlaştırıldı.

---

## [3.2] - 2026-08-21

### Fiyat Arama ve Karşılaştırma Özelliği 💰
- **`search_prices` MCP Aracı**: Ürünler için yerel (Türkiye) ve dünya çapında (Global) fiyat araması ve karşılaştırması yapabilen yeni araç eklendi.
- **Otomatik Kapsam Algılama (`scope="auto"`)**: Girilen sorgu veya para birimine göre yurt içi / yurt dışı pazar yerlerini otomatik tespit etme.
- **Yapılandırılmış Çıktı**: Mağaza adı, ürün başlığı, bulunan fiyatlar ve bağlantıları içeren Markdown karşılaştırma tablosu ve detay listesi.

---

## [3.1] - 2026-08-21

### Yerel Model ve LM Studio Uyumluluğu 🚀
- **Standart MCP Araç Şablonları**: Modellerin boş yanıt (`no content`) üretmesine sebep olan agresif `CRITICAL/ALWAYS` prompt ifadeleri temizlendi.
- **Konfigürasyon Dokümantasyonu**: `mcp.json` sanal ortam ve mutlak yol yönergeleri güncellendi.

---

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