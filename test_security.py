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
print("7. _get_datetime_header() Tests")
print("=" * 55)

_get_datetime_header = ns["_get_datetime_header"]
header = _get_datetime_header()
check("Generates header with Current DateTime", "[Current DateTime:" in header)
check("Contains UTC timestamp", "UTC:" in header)


print()
print("=" * 55)
print("8. ResearchSessionDB & Deep Research Helper Tests")
print("=" * 55)

ResearchSessionDB = ns["ResearchSessionDB"]
_generate_research_angles = ns["_generate_research_angles"]
_extract_domain = ns["_extract_domain"]
deep_research = ns["deep_research"]

# Test angle generation
angles_std = _generate_research_angles("Rust vs Go", is_turkish=False, depth="standard")
check("Generates English angles for standard depth", len(angles_std) == 4)
check("Standard angles contain Alternatives & Comparison", any("Alternatives" in a["angle"] for a in angles_std))

deep_angles = _generate_research_angles("Quantum Computing", is_turkish=False, depth="deep")
check("Generates English angles for deep depth", len(deep_angles) == 5)
check("Deep angles include Future Outlook", any("Future Outlook" in a["angle"] for a in deep_angles))

# Test domain extractor
check("Extracts domain without www", _extract_domain("https://www.nature.com/articles/123") == "nature.com")
check("Extracts clean domain from query URL", _extract_domain("http://techcrunch.com/post?id=1") == "techcrunch.com")

# Test SQLite ResearchSessionDB
db = ResearchSessionDB()
src1_id = db.add_source(
    url="https://example.com/rust",
    title="Rust Performance Analysis",
    domain="example.com",
    angle="Pros & Key Advantages",
    snippet="Rust provides memory safety without garbage collection.",
    content="Rust provides memory safety without garbage collection and near C++ speed."
)
check("Inserts source into SQLite DB and returns ID", src1_id is not None and src1_id > 0)

# Test duplicate URL handling
src1_dup_id = db.add_source(
    url="https://example.com/rust",
    title="Rust Performance Analysis",
    domain="example.com",
    angle="Overview",
    snippet="Duplicate entry test",
    content="Duplicate entry test"
)
check("Handles duplicate source URL gracefully in SQLite", src1_dup_id == src1_id)

db.add_finding(
    source_id=src1_id,
    angle="Pros & Key Advantages",
    key_point="Memory Safety",
    detail="No garbage collector overhead"
)

summary = db.get_summary_by_angle()
check("Retrieves grouped summaries by angle from SQLite", "Pros & Key Advantages" in summary)
check("Summary item contains correct title", summary["Pros & Key Advantages"][0]["title"] == "Rust Performance Analysis")

stats = db.get_stats()
check("Reports correct SQLite DB stats", stats["sources_count"] == 1 and stats["unique_domains"] == 1)
db.close()

# Test deep_research empty input validation
check("Validates empty topic input for deep_research", "Please provide a valid topic" in deep_research(""))

# =======================================================
# 9. HTML Sandbox, Live Preview & Desktop Save Tests
# =======================================================
print()
print("=" * 55)
print("9. HTML Preview & Desktop Save Tests")
print("=" * 55)

render_html_preview = ns["render_html_preview"]
save_code_to_desktop = ns["save_code_to_desktop"]
run_html_sandbox = ns["run_html_sandbox"]
_get_desktop_path = ns["_get_desktop_path"]

# Test render_html_preview validation
check("render_html_preview handles empty input", "Error: HTML code must be a non-empty string." in render_html_preview(""))
preview_res = render_html_preview("<h1>Hello LM Studio</h1>", title="Test App")
check("render_html_preview generates iframe and data-uri", "<iframe" in preview_res and "data:text/html;base64," in preview_res)
check("render_html_preview provides sandbox link", "127.0.0.1:8765" in preview_res)

# Test save_code_to_desktop
desktop_dir = _get_desktop_path()
check("Detects valid desktop directory", desktop_dir.exists())

test_filename = "_test_supermcp_temp.html"
save_res = save_code_to_desktop("<h1>SuperMCP Test</h1>", filename=test_filename, overwrite=True)
check("Saves file to Desktop successfully", "File Successfully Saved to Desktop" in save_res)
test_file_path = desktop_dir / test_filename
check("File exists on Desktop and has content", test_file_path.exists() and "SuperMCP Test" in test_file_path.read_text(encoding="utf-8"))

# Cleanup test file
try:
    if test_file_path.exists():
        test_file_path.unlink()
except Exception:
    pass

# Test security checks for save_code_to_desktop
invalid_ext_res = save_code_to_desktop("malicious", filename="test.exe")
check("Blocks unsafe executable extension on desktop save", "Security Error" in invalid_ext_res)

traversal_res = save_code_to_desktop("content", filename="../../evil.html")
check("Prevents path traversal on desktop save", "evil.html" in traversal_res and ".." not in traversal_res)

# Test run_html_sandbox
sandbox_res = run_html_sandbox("<script>console.log(40 + 2);</script>")
check("run_html_sandbox runs JS and captures console output", "42" in sandbox_res or "Executed successfully" in sandbox_res)

sandbox_blocked = run_html_sandbox("<script>document.cookie = 'test';</script>")
check("run_html_sandbox blocks disallowed patterns", "Blocked - Disallowed pattern detected" in sandbox_blocked)

# =======================================================
# 10. Self-Testing & Iterative Code Evolution Tests
# =======================================================
print()
print("=" * 55)
print("10. Self-Testing & Code Iteration Tests")
print("=" * 55)

test_and_evaluate_code = ns["test_and_evaluate_code"]
iterate_code_session = ns["iterate_code_session"]

# Test test_and_evaluate_code with passing assertions
sample_html = """
<!DOCTYPE html>
<html>
<head><title>Counter App</title></head>
<body>
  <div id="counter-val">0</div>
  <button id="btn-inc">Add</button>
  <script>
    function add(a, b) { return a + b; }
    var count = 0;
    count = add(count, 5);
  </script>
</body>
</html>
"""

eval_res = test_and_evaluate_code(
    html_code=sample_html,
    test_script="expect(add(2, 3)).toBe(5, 'add function works'); assert(count === 5, 'initial count is 5');",
    expected_elements=["#counter-val", "#btn-inc"]
)
check("test_and_evaluate_code confirms successful tests", "TESTS PASSED" in eval_res and "[PASS]" in eval_res)
check("test_and_evaluate_code verifies expected DOM selectors", "Selector `#counter-val` found" in eval_res)

# Test test_and_evaluate_code detecting errors
failing_eval = test_and_evaluate_code(
    html_code=sample_html,
    test_script="assert(count === 999, 'count must be 999');",
    expected_elements=["#non-existent-id"]
)
check("test_and_evaluate_code detects assertion failure", "[FAIL]" in failing_eval and "ISSUES/ERRORS DETECTED" in failing_eval)
check("test_and_evaluate_code detects missing DOM selector", "Selector `#non-existent-id` NOT found" in failing_eval)

# Test iterate_code_session workflow
session_id = "test_calc_session"
iter1_res = iterate_code_session(
    session_id=session_id,
    action="update",
    code="<html><script>var x = 10;</script></html>",
    test_script="assert(x === 10, 'x is 10');",
    note="Initial version"
)
check("iterate_code_session creates version 1", "v1" in iter1_res and "TESTS PASSED" in iter1_res)

iter2_res = iterate_code_session(
    session_id=session_id,
    action="update",
    code="<html><script>var x = 20;</script></html>",
    test_script="assert(x === 20, 'x is 20');",
    note="Updated x to 20"
)
check("iterate_code_session creates version 2", "v2" in iter2_res)

hist_res = iterate_code_session(session_id=session_id, action="history")
check("iterate_code_session retrieves version history", "v1" in hist_res and "v2" in hist_res)

latest_res = iterate_code_session(session_id=session_id, action="get_latest")
check("iterate_code_session retrieves latest version code", "var x = 20" in latest_res)

rollback_res = iterate_code_session(session_id=session_id, action="rollback")
check("iterate_code_session rolls back version", "Rolled Back" in rollback_res and "v1" in rollback_res)

# =======================================================
# 11. Full Simulated DOM Operations Tests
# =======================================================
print()
print("=" * 55)
print("11. Full Simulated DOM Operations Tests")
print("=" * 55)

dom_test_html = """
<!DOCTYPE html>
<html>
<head><title>DOM Sandbox Test</title></head>
<body>
  <div id="container" class="main-box">
    <span class="info-text">Initial Text</span>
  </div>
</body>
</html>
"""

dom_test_script = """
// 1. createElement & appendChild
var btn = document.createElement('button');
btn.id = 'submit-btn';
btn.className = 'btn primary';
btn.textContent = 'Submit';
btn.style.color = 'red';
document.body.appendChild(btn);

assert(document.getElementById('submit-btn') !== null, 'document.getElementById finds created button');
assert(btn.style.color === 'red', 'style property works');

// 2. classList API
btn.classList.add('active');
assert(btn.classList.contains('active'), 'classList.add and contains work');
btn.classList.remove('primary');
assert(!btn.classList.contains('primary'), 'classList.remove works');

// 3. Event listener & dispatchEvent / click
var clicked = false;
btn.addEventListener('click', function(e) {
    clicked = true;
    btn.textContent = 'Clicked!';
});
btn.click();
assert(clicked === true, 'addEventListener and click() work');
assert(btn.textContent === 'Clicked!', 'textContent update on click works');

// 4. querySelector & querySelectorAll
var foundSpan = document.querySelector('.info-text');
assert(foundSpan !== null, 'querySelector with class finds element');
var allButtons = document.querySelectorAll('button');
assert(allButtons.length === 1, 'querySelectorAll finds all button elements');

// 5. attributes API
btn.setAttribute('data-id', '12345');
assert(btn.getAttribute('data-id') === '12345', 'setAttribute and getAttribute work');
"""

dom_eval = test_and_evaluate_code(html_code=dom_test_html, test_script=dom_test_script)
check("Full DOM operations pass in sandbox", "TESTS PASSED" in dom_eval and "[FAIL]" not in dom_eval)


print()
print("=" * 55)
total = passed + failed
print(f"Results: {passed}/{total} tests passed" + (" — ALL OK" if failed == 0 else f" — {failed} FAILED"))
print("=" * 55)

sys.exit(0 if failed == 0 else 1)





