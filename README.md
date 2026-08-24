# LM Studio Web Browser & JS MCP Server

This project is a high-performance and comprehensive **Model Context Protocol (MCP)** server that enables local models running on LM Studio to perform internet searches, read web content, monitor news, execute JavaScript code, translate text, and process documents including PDFs.

## Recent Updates

### v3.3 — Deep Multi-Angle Web Research & Reasoning (SQLite-backed)
- **`deep_research` Tool:** Deconstructs complex topics into multiple critical perspectives (Overview, Pros/Advantages, Cons/Risks, Alternatives/Comparisons, Future Trends) and queries the web concurrently.
- **In-Memory SQLite Research Session:** Deduplicates web sources, extracts structured findings per angle, and normalizes findings in an isolated in-memory SQLite database (`:memory:`).
- **Comparative Synthesis & Reasoning Matrix:** Synthesizes multi-source consensus, nuances, and direct alternative comparison matrices to power high-level reasoning for local models.

### v3.2 — Price Search & Comparison
- **`search_prices` Tool:** Added multi-scope product price research and comparison tool supporting both Turkish domestic stores (Trendyol, Hepsiburada, Akakçe, Amazon TR) and global marketplaces (Amazon, eBay, BestBuy, etc.).
- **Automatic Scope Detection:** Automatically determines whether to search locally or globally based on currency and product query context.

### v3.1 — Local LLM & Tool Calling Compatibility
- **Clean Standardized MCP Prompts:** Streamlined tool descriptions to eliminate aggressive prompting conflicts (`CRITICAL/ALWAYS` directives) that caused local models (Llama, Mistral, Qwen) to generate empty responses.
- **Enhanced LM Studio Integration:** Documented specific virtual environment configuration paths to prevent `Exit Code 1` startup failures.

### v3.0 — Security Hardening
- **Rate Limiting:** Thread-safe `RateLimiter` class enforces a maximum of 30 requests/minute across all tools to prevent DoS conditions.
- **URL Validation:** New `_validate_url()` helper blocks dangerous schemes (`file://`, `javascript:`, `ftp://`), private/local network access (`localhost`, `127.x`, `192.168.x`), and malicious URL patterns before any HTTP request is made.
- **JavaScript Safety:** `execute_javascript` now validates code length (max 10,000 chars) and blocks dangerous patterns including `eval()`, `fetch()`, `document.*`, `XMLHttpRequest`, `require()`, and `process.*`.
- **PDF Security:** `read_pdf` strictly validates `Content-Type: application/pdf` and enforces a 10 MB file size limit.
- **Image Rate Limiting:** `search_images` applies rate limiting to each individual image fetch.
- **Centralized Config:** All security thresholds are managed in a single `SECURITY_CONFIG` dictionary for easy tuning.
- **Safe Error Handling:** Internal error details are never exposed to callers; only generic safe messages are returned.

### v2.0 — Performance and Reliability
- **Parallel Processing:** Using `ThreadPoolExecutor`, reading multiple pages simultaneously has increased speed by 3–5×.
- **Document Support:** Added comprehensive PDF reading capabilities alongside web content processing for diverse data ingestion.
- **ddgs Library:** Migrated to the latest search engine package (`ddgs`) to avoid rate-limit and 403 errors.

## Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `search_web` | Searches the internet via DuckDuckGo and **automatically reads the pages of found results**, returning full content. |
| 2 | `search_news` | Performs a specialized search for news articles. |
| 3 | `read_webpage` | Extracts title, meta information, and main content text from a single webpage. URLs are validated before fetching. |
| 4 | `read_multiple_webpages` | Reads **multiple URLs simultaneously (in parallel)**. Invalid/unsafe URLs are skipped automatically. |
| 5 | `search_and_read` | The most comprehensive research tool: searches, then reads top result pages in parallel and presents them as a unified piece to the model. |
| 6 | `deep_research` | **Multi-angle deep web research & comparative reasoning engine backed by SQLite**. Analyzes perspectives, comparisons, pros/cons, and synthesizes structured insight matrices. |
| 7 | `read_pdf` | Fetches and extracts text from a remote PDF file. Validates Content-Type and enforces a 10 MB size limit. |
| 8 | `execute_javascript` | Executes JavaScript code securely on V8 (5s timeout, 64 MB RAM limit, dangerous patterns blocked). |
| 9 | `get_current_datetime` | Provides current date, time, and day information. |
| 10 | `translate_text` | Translates text to the desired language (default: Turkish). Input length is validated (max 10,000 chars). |
| 11 | `search_images` | Performs image search on the internet and sends found images directly to the model's visual memory. |
| 12 | `search_prices` | Searches and compares product prices locally (Turkey) or globally (worldwide) with structured store & price listings. |

## Security Overview

| Feature | Detail |
|---------|--------|
| Rate Limiting | 30 requests/min (thread-safe) |
| URL Validation | Blocks `file://`, `javascript:`, `ftp://`, localhost, private IPs, malicious patterns |
| JS Execution | Blocks `eval`, `fetch`, DOM access, `require`, `process`, XHR |
| PDF Validation | Strict `Content-Type: application/pdf` check + 10 MB limit |
| Page Size Limit | 5 MB max per page |
| Error Handling | Internal details never exposed to callers |

## Installation

1. Clone the repository or download files to a directory.
2. Create a virtual environment and activate it:

   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   ```

3. Install required libraries:

   ```bash
   pip install -r requirements.txt
   ```

## Testing

Run the security test suite to verify all protections are working:

```bash
python test_security.py
```

Expected output: `34/34 tests passed — ALL OK`

## LM Studio Integration

To add this MCP server to LM Studio:

1. Open LM Studio.
2. Go to **Settings** (or the MCP / Integrations tab) on the menu.
3. Navigate to **MCP Servers** -> **Edit mcp.json**.
4. Configure `mcp.json` using the **absolute path to your virtual environment Python interpreter**:

   ```json
   {
     "mcpServers": {
       "web-and-js-tools": {
         "command": "C:/path/to/lm_supermcp/venv/Scripts/python.exe",
         "args": [
           "C:/path/to/lm_supermcp/mcp_server.py"
         ]
       }
     }
   }
   ```

   *Note: On Windows, always use forward slashes (`/`) in JSON paths.*

## Recommended System Prompt

Paste the following into LM Studio's **System Prompt** field so the model knows its capabilities and seamlessly uses the tools:

```text
You are an intelligent AI assistant equipped with specialized tools for deep web browsing, multi-angle research & reasoning, current news, product price comparison, remote PDF document reading, real-time date/time queries, and JavaScript execution.

- For in-depth topics, architectural decisions, comparative evaluations, and multi-perspective reasoning, use the "deep_research" tool.
- For product pricing or shopping comparisons across Turkish and global stores, use the "search_prices" tool.
- For quick queries about current events, breaking news, or general facts, use "search_web", "search_news", or "search_and_read".
- When asked for the current date or time, use the "get_current_datetime" tool.
- For reading webpage content or remote PDF files, use "read_webpage" or "read_pdf".
- For calculations or code execution, use "execute_javascript".
- For translations, use "translate_text".
- For visual queries or image requests, use "search_images".
```

## Usage Examples

- "Perform deep multi-angle research on Rust vs Go for high-load backend microservices."
- "Search and compare prices for iPhone 16 Pro 256GB."
- "Search the internet: What are today's most important technology news?"
- "What was yesterday's Euro/TL exchange rate?"
- "Write and run a JS program that finds prime numbers from 1 to 1000."
- "Translate this article to English: ..."
- "Read this PDF and summarize it: https://example.com/report.pdf"

## License

This project is open source. Feel free to use, modify, and distribute it as needed.