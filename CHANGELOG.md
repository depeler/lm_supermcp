# Changelog

All notable changes to this project are documented in this file.

## [3.5] - 2026-08-31

### LLM Self-Testing, Iterative Code Refinement & Live Sandbox 🚀🎨🧪
- **`test_and_evaluate_code` MCP Tool**: Allows the model to execute generated HTML, CSS, and JavaScript code in an isolated sandbox, running automated unit tests (`assert`, `expect().toBe()`), DOM selector audits, and runtime error diagnostics for actionable feedback.
- **`iterate_code_session` MCP Tool**: Manages multi-step code evolution and version tracking (`update`, `rollback`, `get_latest`, `history`), enabling the LLM to refine code incrementally from v1 -> v2 -> v3 based on test feedback until reaching perfection.
- **`render_html_preview` MCP Tool**: Renders complete HTML, CSS, and JS web applications in a secure sandbox, providing an interactive iframe (base64 data-URI) embedded directly in the LM Studio chat UI, a local HTTP sandbox link (`http://127.0.0.1:8765/preview_...`), and optional instant launching in the default browser (`open_in_browser=True`).
- **`save_code_to_desktop` MCP Tool**: Saves written web applications, scripts, or code files directly to the user's Desktop with extension security checks and path traversal protection.
- **`run_html_sandbox` MCP Tool**: Runs HTML and JS code headless in a secure V8 engine to capture DOM structure summaries and `console.log` output.

---

## [3.4] - 2026-08-24

### Multi-Angle Deep Web Research & Reasoning Engine (SQLite-backed) 🧠🔬
- **`deep_research` MCP Tool**: Deconstructs any given topic into multiple critical perspectives (Overview, Pros/Advantages, Cons/Risks, Alternatives/Comparisons, Future Trends) and performs concurrent in-depth research across the web.
- **In-Memory SQLite Research Session (`ResearchSessionDB`)**: Implemented a relational in-memory SQLite (`:memory:`) architecture that deduplicates sources and indexes findings and citations by analytical angle.
- **Comparative Synthesis & Reasoning Output**: Synthesizes a structured report featuring multi-source consensus, conflicting viewpoints, and a direct comparative benchmark matrix.

---

## [3.3] - 2026-08-21

### Dynamic Date & Time Injection 🕒
- **Automatic Time Injection (`_get_datetime_header`)**: Prepends the current local date/time, day name, and UTC timestamp to all MCP tool responses. Local LLMs automatically know the exact real-time context on every tool call.
- **Price Search Table Standardization**: Standardized `search_prices` output to always include a structured Markdown comparison table and direct purchase link columns.

---

## [3.2] - 2026-08-21

### Price Search & Comparison 💰
- **`search_prices` MCP Tool**: Added product price search and comparison across both Turkish domestic e-commerce platforms (Trendyol, Hepsiburada, Akakçe, Amazon TR) and global marketplaces (Amazon, eBay, BestBuy, etc.).
- **Automatic Scope Detection (`scope="auto"`)**: Automatically detects regional or global scope based on product search queries and currency context.
- **Structured Output**: Returns structured store names, product titles, detected prices, and direct purchasing URLs.

---

## [3.1] - 2026-08-21

### Local LLM & LM Studio Compatibility 🚀
- **Standardized MCP Tool Prompts**: Cleaned up aggressive prompt directives (`CRITICAL/ALWAYS`) that caused small local models (Llama, Mistral, Qwen) to return empty responses (`no content`).
- **Configuration Documentation**: Updated `mcp.json` virtual environment path configuration guidelines.

---

## [3.0] - 2026-08-13

### Security Hardening 🛡️
- **Rate Limiting**: Thread-safe `RateLimiter` enforces a maximum of 30 requests/minute across all tools.
- **URL Validation**: Blocks dangerous schemes (`file://`, `javascript:`, `ftp://`), private IP ranges, localhost, and malicious patterns.
- **JavaScript Safety**: Disallowed dangerous patterns including `eval()`, `fetch()`, `document.*`, `require()`, and `process.*`.
- **PDF Security**: Added Content-Type validation and a 10 MB maximum file size limit.

### Centralized Configuration 🔧
- All security thresholds and limits are consolidated in a single `SECURITY_CONFIG` dictionary.

---

## [2.0] - 2026-08-13

### Performance Optimizations ⚡
- **Parallel Processing**: Reading multiple pages concurrently via `ThreadPoolExecutor` increased speed by 300–500%.
- **Date Injection**: Added dynamic date headers so models automatically recognize current time context.

### Feature Additions 🎯
- **PDF Processing**: Extracting text from remote PDF documents.
- **ddgs Library**: Migrated to the modern search library to mitigate rate limiting and 403 errors.

---

## [1.0] - Initial Release

Initial release with foundational MCP tools:
- `search_web` - Web search and automated webpage content extraction
- `read_webpage` - Single webpage text extraction
- `execute_javascript` - Secure sandboxed JavaScript execution