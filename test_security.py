"""
Security feature tests for mcp_server.py
Tests: URL validation, RateLimiter, JS dangerous pattern detection, SECURITY_CONFIG
"""

import sys
import re

# Load module in a controlled namespace
with open("mcp_server.py", "r", encoding="utf-8") as f:
    src = f.read()

ns = {"__builtins__": __builtins__}
exec(compile(src, "mcp_server.py", "exec"), ns)

_validate_url = ns["_validate_url"]
RateLimiter = ns["RateLimiter"]
SECURITY_CONFIG = ns["SECURITY_CONFIG"]
_DANGEROUS_JS_PATTERNS = ns["_DANGEROUS_JS_PATTERNS"]
_clean_text = ns["_clean_text"]

passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))
        failed += 1


print("=" * 55)
print("1. _validate_url() Tests")
print("=" * 55)

url_cases = [
    ("https://example.com",                True,  "normal HTTPS"),
    ("http://example.com/path?q=test",     True,  "normal HTTP with query"),
    ("https://sub.domain.com/page",        True,  "subdomain"),
    ("file:///etc/passwd",                 False, "file:// scheme blocked"),
    ("javascript:alert(1)",               False, "javascript: scheme blocked"),
    ("ftp://example.com",                  False, "ftp:// scheme blocked"),
    ("http://localhost/admin",             False, "localhost blocked"),
    ("http://127.0.0.1:8080/api",         False, "127.0.0.1 blocked"),
    ("http://192.168.1.1/router",         False, "192.168.x.x blocked"),
    ("",                                   False, "empty string blocked"),
    ("not-a-url",                          False, "no scheme blocked"),
]

for url, expected, desc in url_cases:
    result, msg = _validate_url(url)
    check(f"{desc}: _validate_url({url!r})", result == expected,
          f"got {result} (msg: {msg})")


print()
print("=" * 55)
print("2. RateLimiter Tests")
print("=" * 55)

rl = RateLimiter(3)
r1 = rl.acquire()
r2 = rl.acquire()
r3 = rl.acquire()
r4 = rl.acquire()  # should be blocked

check("First 3 requests allowed", r1 and r2 and r3)
check("4th request blocked (rate limit)", not r4)

rl2 = RateLimiter(10)
rl2.record()
rl2.record()
check("record() increments timestamp list", len(rl2.timestamps) == 2)


print()
print("=" * 55)
print("3. JavaScript Dangerous Pattern Tests")
print("=" * 55)

def js_blocked(code):
    return any(re.search(p, code, re.IGNORECASE) for p in _DANGEROUS_JS_PATTERNS)

js_cases = [
    ("document.cookie",                    True,  "cookie access"),
    ('fetch("http://evil.com")',           True,  "fetch call"),
    ('eval("alert(1)")',                   True,  "eval call"),
    ("navigator.geolocation",             True,  "geolocation access"),
    ("XMLHttpRequest",                     True,  "XHR"),
    ("require('fs')",                      True,  "require call"),
    ("process.env",                        True,  "process access"),
    ("1 + 1",                              False, "safe math"),
    ("Math.max(1, 2, 3)",                  False, "safe Math call"),
    ("JSON.stringify({a: 1})",            False, "safe JSON"),
    ("[1,2,3].map(x => x * 2)",           False, "safe array op"),
]

for code, expected_blocked, desc in js_cases:
    check(f"{desc}: {code!r}", js_blocked(code) == expected_blocked)


print()
print("=" * 55)
print("4. SECURITY_CONFIG Sanity Tests")
print("=" * 55)

check("requests_per_minute > 0", SECURITY_CONFIG["requests_per_minute"] > 0)
check("max_page_size_bytes >= 1MB", SECURITY_CONFIG["max_page_size_bytes"] >= 1024 * 1024)
check("max_pdf_size_bytes >= 1MB", SECURITY_CONFIG["max_pdf_size_bytes"] >= 1024 * 1024)
check("javascript_timeout_ms > 0", SECURITY_CONFIG["javascript_timeout_ms"] > 0)
check("max_javascript_memory_mb >= 32", SECURITY_CONFIG["max_javascript_memory_mb"] >= 32)
check("max_js_code_length >= 1000", SECURITY_CONFIG["max_js_code_length"] >= 1000)


print()
print("=" * 55)
print("5. _clean_text() Tests")
print("=" * 55)

check("Collapses whitespace",
      _clean_text("hello   world") == "hello world")
check("Strips empty lines",
      "\n\n\n" not in _clean_text("a\n\n\n\nb"))
check("Strips leading/trailing whitespace per line",
      "  spaces  " not in _clean_text("  spaces  \n  more  "))


print()
print("=" * 55)
print("6. Price Extraction & Helper Tests")
print("=" * 55)

_extract_prices_from_text = ns["_extract_prices_from_text"]
_guess_merchant_name = ns["_guess_merchant_name"]

tr_text = "Ürün fiyatı 14.999 TL ve kargo dahil 15.250,50 ₺ olarak satılmaktadır."
tr_prices = _extract_prices_from_text(tr_text, scope="tr")
check("Extracts Turkish Lira prices", len(tr_prices) >= 2 and any("14.999 TL" in p for p in tr_prices))

global_text = "The item costs $299.99 or €275 and £240 on official stores."
global_prices = _extract_prices_from_text(global_text, scope="global")
check("Extracts Global currency prices ($/€/£)", len(global_prices) >= 3 and any("$299.99" in p for p in global_prices))

check("Guesses merchant name from standard URL", _guess_merchant_name("https://www.hepsiburada.com/urun-p-123") == "Hepsiburada")
check("Guesses merchant name from subdomain URL", _guess_merchant_name("https://amazon.com.tr/dp/B001") == "Amazon")


print()
print("=" * 55)
total = passed + failed
print(f"Results: {passed}/{total} tests passed" + (" — ALL OK" if failed == 0 else f" — {failed} FAILED"))
print("=" * 55)

sys.exit(0 if failed == 0 else 1)

