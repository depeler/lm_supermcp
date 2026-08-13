# Katkıda Bulunma Rehberi

Teşekkürler! LM Studio Web Browser & JS MCP Server'a katkıda bulunmaktan mutlu olurum.

## Kurulum

Katkıda bulunmadan önce projeyi yerel olarak kurmanız gerekir:

```bash
# Repoyu klonlayın
git clone https://github.com/depeler/lm_supermcp.git

# Klasöre girin ve virtual environment oluşturun
cd lm_supermcp
python -m venv venv

# Windows'ta virtual environment'i aktif edin
venv\Scripts\activate

# Gerekli kütüphaneleri yükleyin
pip install -r requirements.txt
```

## Kod Kalitesi

### Python Stili

Proje [PEP 8](https://pep8.org/) stiline uyar. `black` ve `flake8` kullanarak otomatik formatlama yapabilirsiniz:

```bash
# Formatla
black mcp_server.py

# Stil kontrolü
flake8 mcp_server.py
```

### Testler

Yeni özellikler eklediğinizden emin olun:

```bash
python test_security.py
python test_mcp.py
```

## Katkı Adımları

1. **Fork edin**: Repoyu GitHub'da fork edin
2. **Branch oluşturun**: `git checkout -b feature/amazing-feature`
3. **Değişiklikler yapın** ve commit'in:
   ```bash
   git commit -m "feat: amazing feature eklendi"
   ```
4. **Push edin**: `git push origin feature/amazing-feature`
5. **Pull Request açın**: GitHub web arayüzünden PR oluşturun

## Commit Mesajları

[Conventional Commits](https://www.conventionalcommits.org/) formatını kullanın:

- `fix:` - Bug düzeltmeleri
- `feat:` - Yeni özellikler
- `docs:` - Dokümantasyon değişiklikleri
- `refactor:` - Kod yeniden düzenleme
- `test:` - Test eklemeleri/düzeltmeleri
- `chore:` - Diğer değişiklikler

## Kod Dergüsü Kuralları

- URL doğrulama korumasını asla atlayın
- JavaScript güvenlik filtrelerini değiştirmeyin
- Rate limit ayarlarını dikkatli değiştirin
- Tüm API isteklerinde hata yönetimi ekleyin

## Sorularınız?

Sorularınız için [README.md](./README.md) dosyasını kontrol edin veya issues sekmesinde açın.

Teşekkürler! 🙏