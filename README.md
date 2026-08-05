# LM Studio Web Browser & JS MCP Server

Bu proje, LM Studio'da çalışan yerel modellerin **internette arama yapabilmesi**, **web sitelerinden bilgi okuyabilmesi**, **haber takibi yapabilmesi**, **JavaScript kodları çalıştırabilmesi** ve **çeviri yapabilmesi** için geliştirilmiş performans odaklı ve kapsamlı bir **Model Context Protocol (MCP)** sunucusudur.

## Son Güncellemeler (Performans ve Güvenilirlik)
- **Paralel İşleme:** `ThreadPoolExecutor` sayesinde çoklu sayfalar eş zamanlı (paralel) okunarak hız 3-5 kat artırıldı.
- **Tarih Enjeksiyonu:** Modelin bugünün tarihini otomatik bilmesi için araç açıklamalarına sistem tarihi dinamik olarak gömüldü.
- **ddgs Kütüphanesi:** Rate-limit ve 403 engellerine takılmamak adına arama motoru paketi en güncel altyapıya (`ddgs`) taşındı.

## Araçlar (Tools)

| # | Araç | Açıklama |
|---|------|----------|
| 1 | `search_web` | İnternette DuckDuckGo üzerinden arama yapar ve **bulunan sonuçların sayfalarını otomatik olarak okuyup** tam içerikle döner. |
| 2 | `search_news` | Haberlere özel güncel arama yapar. |
| 3 | `read_webpage` | Tek bir sayfanın başlık, meta ve ana içerik metnini akıllıca çıkarır. |
| 4 | `read_multiple_webpages` | Verilen birden fazla URL'yi **aynı anda eş zamanlı (paralel)** okur ve birleştirir. |
| 5 | `search_and_read` | En kapsamlı araştırma aracı: Arama yapar ve en üstteki sonuç sayfalarını eş zamanlı okuyup tek parça halinde modele sunar. |
| 6 | `execute_javascript` | V8 motoru üzerinde güvenli (5sn timeout, 64MB RAM) JS kodu çalıştırır. |
| 7 | `get_current_datetime` | Anlık tarih, saat ve gün bilgisini verir (model çoğu zaman bunu açıklamadan kendi anlar). |
| 8 | `translate_text` | Metni istenilen dile çevirir (varsayılan: Türkçe). |
| 9 | `search_images` | (YENİ) İnternette görsel araması yapar ve bulduğu fotoğrafları doğrudan modelin gözlerine (görsel hafızasına) gönderir. |

## Kurulum

1. Depoyu klonlayın veya dosyaları bir klasöre indirin.
2. Bir sanal ortam oluşturun ve aktif edin:
   ```bash
   python -m venv venv
   # Windows için:
   venv\Scripts\activate
   # macOS/Linux için:
   source venv/bin/activate
   ```
3. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

## LM Studio Entegrasyonu

Bu MCP sunucusunu LM Studio'ya eklemek için:

1. LM Studio'yu açın.
2. Sağ taraftaki menüden **Program** (veya ayarlar) bölümüne gidin.
3. **MCP Servers** -> **Edit mcp.json** yolunu izleyin.
4. `mcp.json` dosyasını aşağıdaki gibi düzenleyin (`command` ve `args` kısımlarında bilgisayarınızdaki tam/mutlak yolları kullanın):

```json
{
  "mcpServers": {
    "web-and-js-tools": {
      "command": "C:/Users/kaant/Documents/antigravity/lucid-pasteur/venv/Scripts/python.exe",
      "args": [
        "C:/Users/kaant/Documents/antigravity/lucid-pasteur/mcp_server.py"
      ]
    }
  }
}
```

*Not: Windows üzerindeyseniz, ters eğik çizgi (`\`) yerine düz eğik çizgi (`/`) kullanmaya özen gösterin.*

## Önerilen System Prompt

Modelin araçları inat etmeden, aktif olarak kullanabilmesi için LM Studio'daki **System Prompt** alanına şunu yapıştırın:

```text
Sen güncel internete doğrudan bağlı olan gelişmiş bir yapay zekasın. Canlı internete erişimin, JavaScript çalıştırma yeteneğin, çeviri aracın ve KULLANICIYA GÖRSEL/FOTOĞRAF GÖSTERME yeteneğin var.
ASLA "Ben bir yapay zekayım, güncel bilgileri bilemem", "Gerçek zamanlı bilgiye erişemem" veya "Doğrudan görsel/fotoğraf paylaşamam" GİBİ CÜMLELER KURMA! Bu kesinlikle yasaktır. Sen araçlarını (tools) kullanarak bunları yapabilirsin.
- Bilmediğin veya güncel olan bir şey sorulduğunda ZORUNLU OLARAK "search_web", "search_news" veya "search_and_read" aracını kullan.
- Kullanıcı senden bir fotoğraf veya görsel görmek istediğinde ZORUNLU OLARAK "search_images" aracını kullan. Bu araç senin yerine kullanıcıya fotoğrafı doğrudan gösterecektir.
- Hesaplama veya algoritma gerektiğinde "execute_javascript" ile kod çalıştır.
- Yabancı dildeki metinleri çevirmek için "translate_text" kullan.
```

## Kullanım Örnekleri

- "İnternetten araştır: Bugünün en önemli teknoloji haberleri neler?"
- "Dünkü Euro/TL kuru ne kadardı?"
- "1'den 1000'e kadar olan asal sayıları bulan bir JS kodu yaz ve çalıştır."
- "Bu makaleyi Türkçeye çevir: ..."
