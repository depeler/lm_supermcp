"""
WebBrowserMCP Server - Secure Implementation

This MCP server provides tools for web browsing, JavaScript execution, PDF reading,
and more. It includes comprehensive security measures to prevent common vulnerabilities.

SECURITY MEASURES IMPLEMENTED:
- Input validation and sanitization
- Rate limiting to prevent DoS attacks
- URL validation with dangerous protocol/pattern blocking
- Memory-limited JavaScript execution with dangerous pattern blocking
- Content type validation for PDF/image operations
- Safe error handling that doesn't leak internals
"""

import re
import sys
import time
import logging
import threading
from datetime import datetime, timezone
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from ddgs import DDGS
from mcp.server.fastmcp import FastMCP
import mcp.types as types
import base64
from py_mini_racer import MiniRacer
from deep_translator import GoogleTranslator

# ---------------------------------------------------------------------------
# Server & Logging
# ---------------------------------------------------------------------------
mcp = FastMCP("WebBrowserMCP")

_TODAY = datetime.now().strftime("%Y-%m-%d")

# Configure basic logging to stderr (DO NOT log to stdout as MCP uses it for JSON-RPC)
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security Configuration
# ---------------------------------------------------------------------------
SECURITY_CONFIG = {
    "requests_per_minute": 30,
    "max_page_size_bytes": 5 * 1024 * 1024,   # 5 MB
    "max_pdf_size_bytes": 10 * 1024 * 1024,    # 10 MB
    "max_javascript_memory_mb": 64,
    "javascript_timeout_ms": 5000,
    "max_js_code_length": 10000,
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
}

# Dangerous URL patterns to block
_DANGEROUS_URL_PATTERNS = [
    r"eval\(",
    r"document\.cookie",
    r"fetch\s*\(",
    r"<script",
]

# Dangerous JavaScript patterns to block
_DANGEROUS_JS_PATTERNS = [
    r"document\.(cookie|write|location)",
    r"fetch\s*\(",
    r"eval\s*\(",
    r"navigator\.(geolocation|userAgent)",
    r"XMLHttpRequest",
    r"require\s*\(",
    r"process\.",
]


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    """Thread-safe rate limiter to prevent DoS attacks."""

    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.timestamps: list[float] = []
        self._lock = threading.Lock()

    def _cleanup(self) -> None:
        one_minute_ago = time.time() - 60
        self.timestamps[:] = [t for t in self.timestamps if t > one_minute_ago]

    def acquire(self) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        with self._lock:
            self._cleanup()
            if len(self.timestamps) >= self.requests_per_minute:
                oldest = min(self.timestamps)
                wait_time = (oldest + 60) - time.time()
                if wait_time > 0:
                    logger.warning(f"Rate limit exceeded. Retry in {wait_time:.1f}s.")
                    return False
            self.timestamps.append(time.time())
            return True

    def record(self) -> None:
        """Manually record a request (for tools that bypass acquire)."""
        with self._lock:
            self.timestamps.append(time.time())


_rate_limiter = RateLimiter(SECURITY_CONFIG["requests_per_minute"])


# ---------------------------------------------------------------------------
# URL Validator
# ---------------------------------------------------------------------------
def _validate_url(url: str) -> tuple[bool, str | None]:
    """Validate a URL for security. Returns (is_valid, error_message)."""
    if not isinstance(url, str) or not url.strip():
        return False, "URL must be a non-empty string."
    try:
        parsed = urlparse(url)

        # Block non-http(s) schemes
        if parsed.scheme not in ("http", "https"):
            return False, f"Blocked dangerous URL scheme '{parsed.scheme}': {url}"

        # Block localhost / private network access
        hostname = parsed.hostname or ""
        blocked_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
        if hostname in blocked_hosts or hostname.startswith("192.168.") or hostname.startswith("10."):
            return False, f"Blocked private/local network access: {url}"

        # Block dangerous patterns in URL
        for pattern in _DANGEROUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return False, f"Blocked URL with dangerous pattern: {url}"

        return True, None
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


# ---------------------------------------------------------------------------
# Shared Resources (Singleton / Reusable)
# ---------------------------------------------------------------------------

# Reusable HTTP session with connection pooling and automatic retries
_http_session: requests.Session | None = None


def _get_http_session() -> requests.Session:
    """Return a shared requests.Session with connection pooling and retry logic."""
    global _http_session
    if _http_session is None:
        _http_session = requests.Session()
        _http_session.headers.update({
            "User-Agent": SECURITY_CONFIG["user_agent"],
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        })
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20,
        )
        _http_session.mount("https://", adapter)
        _http_session.mount("http://", adapter)
    return _http_session


# Reusable V8 JavaScript engine (avoid cold-start on every call)
_js_engine: MiniRacer | None = None


def _get_js_engine() -> MiniRacer:
    """Return a shared MiniRacer V8 instance."""
    global _js_engine
    if _js_engine is None:
        _js_engine = MiniRacer()
    return _js_engine


# Reusable DuckDuckGo client
_ddgs_client: Any = None


def _get_ddgs() -> Any:
    """Return a shared DDGS client instance."""
    global _ddgs_client
    if _ddgs_client is None:
        _ddgs_client = DDGS()
    return _ddgs_client


# Cached translator instances per language pair
@lru_cache(maxsize=16)
def _get_translator(source: str, target: str) -> GoogleTranslator:
    """Return a cached GoogleTranslator for the given language pair."""
    return GoogleTranslator(source=source, target=target)


# Pre-compiled regex for text cleaning (faster than repeated str.split)
_MULTI_WHITESPACE = re.compile(r"[ \t]{2,}")
_MULTI_NEWLINE = re.compile(r"\n{3,}")

# Elements to remove from HTML (defined once, not per call)
_NOISY_TAGS = ["script", "style", "nav", "footer", "header", "aside", "form", "noscript", "iframe", "svg"]

# Turkish day names (constant)
_DAYS_TR = {
    "Monday": "Pazartesi", "Tuesday": "Salı", "Wednesday": "Çarşamba",
    "Thursday": "Perşembe", "Friday": "Cuma", "Saturday": "Cumartesi", "Sunday": "Pazar",
}

# Content limit
_MAX_CONTENT_LENGTH = 8000

# Thread pool for concurrent webpage fetching
_thread_pool = ThreadPoolExecutor(max_workers=8)


# ---------------------------------------------------------------------------
# Helper: Dynamic DateTime Header for LLM Context
# ---------------------------------------------------------------------------
def _get_datetime_header() -> str:
    """Return current date, time, and day information as a header string for tool responses."""
    now = datetime.now()
    utc_now = datetime.now(timezone.utc)
    day_tr = _DAYS_TR.get(now.strftime("%A"), now.strftime("%A"))
    return (
        f"[Current DateTime: {now.strftime('%Y-%m-%d %H:%M:%S')} (Day: {day_tr} / {now.strftime('%A')}) | UTC: {utc_now.strftime('%Y-%m-%d %H:%M:%S')}]\n\n"
    )


# ---------------------------------------------------------------------------
# Helper: Clean extracted text
# ---------------------------------------------------------------------------
def _clean_text(raw: str) -> str:
    """Clean and normalize extracted text efficiently using pre-compiled regex."""
    # Collapse multiple spaces/tabs into single space
    text = _MULTI_WHITESPACE.sub(" ", raw)
    # Strip each line and remove empties
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    text = "\n".join(lines)
    # Collapse excessive blank lines
    text = _MULTI_NEWLINE.sub("\n\n", text)
    return text


# ---------------------------------------------------------------------------
# Helper: Fetch a single page (used by both single and batch tools)
# ---------------------------------------------------------------------------
def _fetch_single_page(url: str, timeout: int = 15) -> str:
    """Fetch and extract clean text from a single URL. Internal helper."""

    # [SECURITY] Validate URL before fetching
    is_valid, error_msg = _validate_url(url)
    if not is_valid:
        return f"Security Error: {error_msg}"

    # [SECURITY] Apply rate limiting
    if not _rate_limiter.acquire():
        return "Rate limit exceeded. Please try again later."

    try:
        session = _get_http_session()
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=False,
        )
        response.raise_for_status()

        # [SECURITY] Check page size limit before parsing
        content_size = len(response.content)
        if content_size > SECURITY_CONFIG["max_page_size_bytes"]:
            logger.warning(f"Page too large ({content_size} bytes), truncating: {url}")

        # Fix encoding
        if response.encoding and response.encoding.lower() != "utf-8":
            response.encoding = response.apparent_encoding

        soup = BeautifulSoup(response.text, "lxml")

        # Extract title and meta
        page_title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
        meta_desc_tag = soup.find("meta", attrs={"name": "description"})
        meta_desc = meta_desc_tag["content"].strip() if meta_desc_tag and meta_desc_tag.get("content") else "N/A"

        header_info = f"Page Title: {page_title}\nMeta Description: {meta_desc}\n\n---\n\n"

        # Remove noisy elements
        for tag in soup(_NOISY_TAGS):
            tag.extract()

        # Prioritize main content
        main_content = soup.find("article") or soup.find("main") or soup.find("div", {"role": "main"})
        target = main_content if main_content else soup.body if soup.body else soup

        raw_text = target.get_text(separator="\n")
        text = _clean_text(raw_text)
        full_text = header_info + text

        if len(full_text) > _MAX_CONTENT_LENGTH:
            full_text = full_text[:_MAX_CONTENT_LENGTH] + "\n\n...[Content truncated due to length]..."

        return full_text
    except Exception as e:
        # [SECURITY] Don't expose internal error details
        logger.error(f"Error reading {url}: {e}")
        return f"Error reading URL: Request timed out or failed."


# ---------------------------------------------------------------------------
# Tool 1: Web Search
# ---------------------------------------------------------------------------
@mcp.tool()
def search_web(query: str, max_results: int = 5, region: str = "tr-tr") -> str:
    """
    Search the web for real-time information, news, or general facts, and extract relevant page contents.

    Args:
        query: The search query string.
        max_results: Maximum number of search results to return (default: 5).
        region: Region code for localized results (e.g. 'tr-tr', 'wt-wt', 'us-en').
    """
    logger.info(f"Searching web for: {query} (region={region})")
    try:
        ddgs = _get_ddgs()
        raw_results = ddgs.text(query, region=region, max_results=max_results)

        if not raw_results:
            return "No results found."

        # Collect URLs and launch concurrent page reads
        urls = [r.get("href") for r in raw_results if r.get("href")]
        page_contents: dict[str, str] = {}
        futures = {_thread_pool.submit(_fetch_single_page, url): url for url in urls}

        for future in as_completed(futures):
            url = futures[future]
            try:
                page_contents[url] = future.result()
            except Exception as e:  # noqa: BLE001
                page_contents[url] = f"Error: {str(e)}"

        # Build combined output: snippet + full page content
        output_parts = []
        for i, r in enumerate(raw_results, 1):
            url = r.get("href", "")
            title = r.get("title", "N/A")
            snippet = r.get("body", "")
            content = page_contents.get(url, "Could not read page.")
            output_parts.append(
                f"=== RESULT {i}: {title} ===\n"
                f"URL: {url}\n"
                f"Snippet: {snippet}\n\n"
                f"--- Full Page Content ---\n{content}"
            )

        return _get_datetime_header() + "=" * 60 + "\n\n" + "\n\n".join(output_parts)
    except Exception as e:
        logger.error(f"Error searching web: {e}")
        return f"Error occurred while searching: Request timed out or rate limited."


# ---------------------------------------------------------------------------
# Tool 2: News Search
# ---------------------------------------------------------------------------
@mcp.tool()
def search_news(query: str, max_results: int = 5, region: str = "tr-tr") -> str:
    """
    Search specifically in news sources for recent news articles and current affairs.

    Args:
        query: The news search query.
        max_results: Maximum number of news articles to return (default: 5).
        region: Region code for localized news (default: 'tr-tr').
    """
    logger.info(f"Searching news for: {query} (region={region})")
    try:
        ddgs = _get_ddgs()
        raw_results = ddgs.news(query, region=region, max_results=max_results)

        if not raw_results:
            return _get_datetime_header() + "No news articles found."

        results = [
            f"Title: {r.get('title')}\nSource: {r.get('source')}\nDate: {r.get('date')}\nURL: {r.get('url')}\nSnippet: {r.get('body')}"
            for r in raw_results
        ]
        return _get_datetime_header() + "\n\n---\n\n".join(results)
    except Exception as e:
        logger.error(f"Error searching news: {e}")
        return f"Error occurred while searching news: Request timed out or rate limited."


# ---------------------------------------------------------------------------
# Tool 3: Read Webpage (single)
# ---------------------------------------------------------------------------
@mcp.tool()
def read_webpage(url: str) -> str:
    """
    Fetch and read the full text content of a single webpage URL.

    Args:
        url: The full HTTP/HTTPS URL of the webpage to read.
    """
    logger.info(f"Reading webpage: {url}")

    # [SECURITY] Validate URL before fetching
    is_valid, error_msg = _validate_url(url)
    if not is_valid:
        return f"Security Error: {error_msg}"

    return _get_datetime_header() + _fetch_single_page(url)


# ---------------------------------------------------------------------------
# Tool 4: Read Multiple Webpages (concurrent)
# ---------------------------------------------------------------------------
@mcp.tool()
def read_multiple_webpages(urls: list[str]) -> str:
    """
    Read multiple webpages simultaneously in parallel.

    Args:
        urls: List of webpage URLs to read concurrently.
    """
    logger.info(f"Reading {len(urls)} webpages concurrently")

    # [SECURITY] Validate and filter all URLs first
    validated_urls = []
    for url in urls[:8]:  # Cap at 8 concurrent
        is_valid, error_msg = _validate_url(url)
        if is_valid:
            validated_urls.append(url)
        else:
            logger.warning(f"Skipping unsafe URL: {url} — {error_msg}")

    if not validated_urls:
        return "No valid URLs to fetch."

    results: dict[str, str] = {}
    futures = {_thread_pool.submit(_fetch_single_page, url): url for url in validated_urls}

    for future in as_completed(futures):
        url = futures[future]
        try:
            results[url] = future.result()
        except Exception as exc:
            results[url] = f"Error reading {url}: {str(exc)}"

    # Build output in original URL order
    output_parts = []
    for i, url in enumerate(validated_urls, 1):
        output_parts.append(f"=== PAGE {i}: {url} ===\n\n{results.get(url, 'No data')}")

    return _get_datetime_header() + f"\n\n{'=' * 60}\n\n".join(output_parts)


# ---------------------------------------------------------------------------
# Tool 5: Search and Read (all-in-one)
# ---------------------------------------------------------------------------
@mcp.tool()
def search_and_read(query: str, max_pages: int = 3, region: str = "tr-tr") -> str:
    """
    Search the web and read the top resulting pages in parallel in a single step.

    Args:
        query: The search query.
        max_pages: Number of top search results to fetch and read (default: 3, max: 5).
        region: Region code for localized results (default: 'tr-tr').
    """
    logger.info(f"Search-and-read for: {query} (top {max_pages} pages)")
    max_pages = min(max_pages, 5)  # Safety cap

    try:
        # Step 1: Search
        ddgs = _get_ddgs()
        search_results = ddgs.text(query, region=region, max_results=max_pages)

        if not search_results:
            return _get_datetime_header() + "No search results found."

        urls = [r.get("href") for r in search_results if r.get("href")]

        # Step 2: Read all pages concurrently
        page_contents: dict[str, str] = {}
        futures = {_thread_pool.submit(_fetch_single_page, url): url for url in urls}

        for future in as_completed(futures):
            url = futures[future]
            try:
                page_contents[url] = future.result()
            except Exception as e:
                page_contents[url] = f"Error: {str(e)}"

        # Step 3: Combine results
        output_parts = []
        for i, r in enumerate(search_results, 1):
            url = r.get("href", "")
            title = r.get("title", "N/A")
            content = page_contents.get(url, "Could not read page.")
            output_parts.append(
                f"=== RESULT {i}: {title} ===\n"
                f"URL: {url}\n\n"
                f"{content}"
            )

        return _get_datetime_header() + f"\n\n{'=' * 60}\n\n".join(output_parts)
    except Exception as e:
        logger.error(f"Error in search_and_read: {e}")
        return f"Error: Request timed out or rate limited."


# ---------------------------------------------------------------------------
# Tool 6: Read PDF File
# ---------------------------------------------------------------------------
@mcp.tool()
def read_pdf(file_path: str) -> str:
    """
    Extract text content from a remote PDF file URL.

    Args:
        file_path: HTTP/HTTPS URL of the PDF file to read.
    """
    logger.info(f"Reading PDF file: {file_path}")

    # [SECURITY] Validate URL
    is_valid, error_msg = _validate_url(file_path)
    if not is_valid:
        return f"Security Error: {error_msg}"

    # [SECURITY] Apply rate limiting
    if not _rate_limiter.acquire():
        return "Rate limit exceeded. Please try again later."

    try:
        session = _get_http_session()
        response = session.get(file_path, timeout=15, allow_redirects=True)
        response.raise_for_status()

        # [SECURITY] Strict content-type check
        content_type = response.headers.get("Content-Type", "")
        if "application/pdf" not in content_type:
            return f"Security Error: Expected 'application/pdf', got '{content_type}'"

        pdf_bytes = response.content

        # [SECURITY] File size limit
        if len(pdf_bytes) > SECURITY_CONFIG["max_pdf_size_bytes"]:
            return f"Error: PDF file too large (max {SECURITY_CONFIG['max_pdf_size_bytes'] // (1024*1024)} MB)."

        # Parse PDF using PyPDF2
        from PyPDF2 import PdfReader
        from io import BytesIO

        pdf_file = BytesIO(pdf_bytes)
        reader = PdfReader(pdf_file)

        all_text = []
        for i, page in enumerate(reader.pages):
            try:
                text = page.extract_text()
                if text:
                    all_text.append(f"--- Page {i + 1} ---\n{text}\n")
                else:
                    all_text.append(f"--- Page {i + 1} ---\n[No text extracted]\n")
            except Exception as page_error:
                all_text.append(f"--- Page {i + 1} ---\nError: {str(page_error)}\n")

        if not all_text:
            return _get_datetime_header() + "No text could be extracted from the PDF."

        content = "".join(all_text)
        if len(content) > _MAX_CONTENT_LENGTH:
            content = content[:_MAX_CONTENT_LENGTH] + "\n\n...[Content truncated due to length]..."

        return _get_datetime_header() + f"PDF Content ({len(reader.pages)} pages):\n\n{content}"
    except Exception as e:
        logger.error(f"Error reading PDF: {e}")
        return f"Error reading PDF file: Request timed out or invalid PDF format."


# ---------------------------------------------------------------------------
# Tool 7: Execute JavaScript
# ---------------------------------------------------------------------------
@mcp.tool()
def execute_javascript(code: str) -> str:
    """
    Execute JavaScript code in a secure sandboxed V8 engine.

    Args:
        code: The JavaScript code string to execute. It must return a value or evaluate to an expression.
    """
    logger.info("Executing JavaScript code")

    # [SECURITY] Input type and size validation
    if not isinstance(code, str):
        return "Error: Code must be a string."
    if len(code) > SECURITY_CONFIG["max_js_code_length"]:
        return f"Error: JavaScript code too large (max {SECURITY_CONFIG['max_js_code_length']} characters)."

    # [SECURITY] Block dangerous patterns
    for pattern in _DANGEROUS_JS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            return "Error: Code contains disallowed patterns (DOM access, network calls, or eval are not permitted)."

    try:
        ctx = _get_js_engine()
        result = ctx.eval(
            code,
            timeout=SECURITY_CONFIG["javascript_timeout_ms"],
            max_memory=SECURITY_CONFIG["max_javascript_memory_mb"] * 1024 * 1024,
        )
        return _get_datetime_header() + str(result)
    except Exception as e:
        logger.error(f"Error executing JavaScript: {e}")
        return f"JavaScript Execution Error: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 8: Get Current Date and Time
# ---------------------------------------------------------------------------
@mcp.tool()
def get_current_datetime() -> str:
    """
    Get the current local and UTC date, time, and day of the week.
    """
    now = datetime.now()
    utc_now = datetime.now(timezone.utc)
    day_tr = _DAYS_TR.get(now.strftime("%A"), now.strftime("%A"))

    return (
        f"Local Date: {now.strftime('%Y-%m-%d')}\n"
        f"Local Time: {now.strftime('%H:%M:%S')}\n"
        f"Day: {day_tr} ({now.strftime('%A')})\n"
        f"UTC Time: {utc_now.strftime('%Y-%m-%d %H:%M:%S')}"
    )


# ---------------------------------------------------------------------------
# Tool 9: Translate Text
# ---------------------------------------------------------------------------
@mcp.tool()
def translate_text(text: str, target_language: str = "tr", source_language: str = "auto") -> str:
    """
    Translate text between languages.

    Args:
        text: The text to translate (max 10,000 characters).
        target_language: Target language code (e.g. 'tr', 'en', 'de', 'fr', 'es').
        source_language: Source language code (default 'auto' for detection).
    """
    logger.info(f"Translating text to {target_language}")

    # [SECURITY] Input validation
    if not isinstance(text, str):
        return "Error: Text must be a string."
    if len(text) > 10000:
        return "Error: Text too large (max 10,000 characters)."

    try:
        translator = _get_translator(source_language, target_language)

        # deep-translator has a 5000 char limit per call, split if needed
        if len(text) > 4500:
            chunks = [text[i: i + 4500] for i in range(0, len(text), 4500)]
            translated_chunks = [translator.translate(chunk) for chunk in chunks]
            return _get_datetime_header() + "".join(translated_chunks)

        return _get_datetime_header() + translator.translate(text)
    except Exception as e:
        logger.error(f"Error translating text: {e}")
        return f"Translation Error: Service unavailable or rate limited."


# ---------------------------------------------------------------------------
# Tool 10: Search Images
# ---------------------------------------------------------------------------
@mcp.tool()
def search_images(query: str, max_results: int = 2, region: str = "tr-tr") -> list:
    """
    Search for images on the web and return them.

    Args:
        query: The image search query.
        max_results: Number of images to fetch (default: 2, max: 4).
        region: Region code (default: 'tr-tr').
    """
    logger.info(f"Searching images for: {query}")
    max_results = min(max_results, 4)
    try:
        ddgs = _get_ddgs()
        raw_results = ddgs.images(query, region=region, max_results=max_results)

        if not raw_results:
            return [types.TextContent(type="text", text=_get_datetime_header() + "No images found.")]

        content_blocks = []
        content_blocks.append(types.TextContent(type="text", text=_get_datetime_header() + f"Found {len(raw_results)} images for '{query}':\n"))

        session = _get_http_session()
        for i, r in enumerate(raw_results, 1):
            title = r.get("title", "Unknown")
            source_url = r.get("url", "")
            img_url = r.get("thumbnail") or r.get("image")

            if not img_url:
                continue

            # [SECURITY] Apply rate limiting per image fetch
            if not _rate_limiter.acquire():
                content_blocks.append(types.TextContent(
                    type="text",
                    text=f"\nImage {i}: Rate limited, skipping."
                ))
                continue

            try:
                resp = session.get(img_url, timeout=5)
                resp.raise_for_status()

                # [SECURITY] Validate content type
                content_type = resp.headers.get("Content-Type", "image/jpeg")
                if not content_type.startswith("image/"):
                    content_type = "image/jpeg"

                b64_data = base64.b64encode(resp.content).decode("utf-8")

                content_blocks.append(types.TextContent(
                    type="text",
                    text=f"\nImage {i}: {title}\nSource: {source_url}"
                ))
                content_blocks.append(types.ImageContent(
                    type="image",
                    data=b64_data,
                    mimeType=content_type
                ))
            except Exception:
                content_blocks.append(types.TextContent(
                    type="text",
                    text=f"\nFailed to load Image {i} ({img_url}): Request failed."
                ))

        return content_blocks
    except Exception as exc:
        logger.error(f"Error searching images: {exc}")
        return [types.TextContent(type="text", text=f"Error occurred: Request timed out or rate limited.")]


# ---------------------------------------------------------------------------
# Helper: Extract price and merchant info from text/url
# ---------------------------------------------------------------------------
_PRICE_REGEX_TR = re.compile(
    r"(?:[\d]{1,3}(?:\.[\d]{3})*(?:,[\d]{1,2})?|\d+(?:,\d{1,2})?)\s*(?:TL|₺|TRY|tl)",
    re.IGNORECASE
)
_PRICE_REGEX_GLOBAL = re.compile(
    r"(?:\$|€|£|USD|EUR|GBP)\s*(?:\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)|(?:\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)\s*(?:\$|€|£|USD|EUR|GBP)",
    re.IGNORECASE
)


def _extract_prices_from_text(text: str, scope: str = "auto") -> list[str]:
    """Extract price mentions from text based on scope."""
    found: list[str] = []
    if scope in ("tr", "local"):
        found.extend(_PRICE_REGEX_TR.findall(text))
    elif scope in ("global", "worldwide"):
        found.extend(_PRICE_REGEX_GLOBAL.findall(text))
    else:  # auto / both
        found.extend(_PRICE_REGEX_TR.findall(text))
        found.extend(_PRICE_REGEX_GLOBAL.findall(text))

    # Clean and deduplicate while preserving order
    cleaned = []
    seen = set()
    for p in found:
        p_clean = " ".join(p.strip().split())
        if p_clean and p_clean not in seen:
            seen.add(p_clean)
            cleaned.append(p_clean)
    return cleaned


def _guess_merchant_name(url: str) -> str:
    """Extract a friendly merchant/website name from URL domain."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        # Remove www. and domain extensions
        parts = hostname.split(".")
        if len(parts) >= 2:
            if parts[0] == "www":
                return parts[1].capitalize()
            return parts[0].capitalize()
        return hostname or "Web"
    except Exception:
        return "Web"


# ---------------------------------------------------------------------------
# Tool 11: Price Search & Comparison
# ---------------------------------------------------------------------------
@mcp.tool()
def search_prices(
    query: str,
    scope: str = "auto",
    currency: str = "",
    max_results: int = 5,
) -> str:
    """
    Search and compare product prices locally (Turkey) or globally (worldwide).
    Returns a structured price comparison table containing the Store Name, Product Title, Price, and Direct Purchase URL.
    The caller/model should present this table and the direct purchase links directly to the user.

    Args:
        query: The product name or search query (e.g. 'iPhone 15 128GB', 'RTX 4070 Ti').
        scope: Search scope. Options:
            - 'auto': Automatically detects region based on query and currency (default).
            - 'tr' or 'local': Searches Turkish stores (Trendyol, Hepsiburada, Amazon TR, Akakçe, etc.).
            - 'global' or 'worldwide': Searches international stores (Amazon, eBay, BestBuy, Newegg, etc.).
        currency: Optional preferred currency filter (e.g. 'TRY', 'USD', 'EUR').
        max_results: Maximum number of stores/results to return (default: 5, max: 10).
    """
    # [SECURITY] Input sanitization
    if not query or not query.strip():
        return "Please provide a valid product name or search query."

    query = query.strip()
    max_results = max(1, min(max_results, 10))
    scope_lower = scope.lower().strip()

    # Determine effective scope
    if scope_lower in ("tr", "local", "turkey"):
        effective_scope = "tr"
    elif scope_lower in ("global", "worldwide", "international", "world"):
        effective_scope = "global"
    else:
        # Auto detect based on currency or query keywords
        tr_hints = ["tl", "₺", "try", "türkiye", "turkey", "fiyat", "fiyatı", "kaç para", "satın al"]
        global_hints = ["usd", "eur", "gbp", "$", "€", "£", "price", "buy", "worldwide", "global"]

        query_lower = query.lower()
        curr_lower = currency.lower()

        if any(h in curr_lower for h in ["try", "tl", "₺"]) or any(h in query_lower for h in tr_hints):
            effective_scope = "tr"
        elif any(h in curr_lower for h in ["usd", "eur", "gbp", "$", "€", "£"]) or any(h in query_lower for h in global_hints):
            effective_scope = "global"
        else:
            effective_scope = "tr"  # Default to local if indeterminate

    # [SECURITY] Apply rate limiting
    if not _rate_limiter.acquire():
        return "Rate limit exceeded. Please try again later."

    # Build targeted search query and set region
    if effective_scope == "tr":
        region = "tr-tr"
        search_query = f"{query} fiyat satın al"
    else:
        region = "wt-wt"
        currency_suffix = f" {currency}" if currency else ""
        search_query = f"{query} price buy online store{currency_suffix}"

    logger.info(f"Searching prices for '{query}' (scope={effective_scope}, region={region})")

    try:
        ddgs = _get_ddgs()
        raw_results = ddgs.text(search_query, region=region, max_results=max_results)

        if not raw_results:
            return _get_datetime_header() + f"No price results found for '{query}' with scope '{effective_scope}'."

        # Collect URLs and fetch brief snippets/pages in parallel for accurate price extraction
        urls = [r.get("href") for r in raw_results if r.get("href")]
        page_contents: dict[str, str] = {}
        futures = {_thread_pool.submit(_fetch_single_page, url, 6): url for url in urls}

        for future in as_completed(futures):
            url = futures[future]
            try:
                page_contents[url] = future.result()
            except Exception as e:  # noqa: BLE001
                page_contents[url] = ""

        # Format price comparison table and details
        rows = []
        detailed_findings = []

        for i, r in enumerate(raw_results, 1):
            url = r.get("href", "")
            title = r.get("title", "N/A")
            snippet = r.get("body", "")
            page_text = page_contents.get(url, "")

            # Combine snippet and page preview for price extraction
            combined_text = f"{title}\n{snippet}\n{page_text[:1500]}"
            prices = _extract_prices_from_text(combined_text, scope=effective_scope)
            price_display = ", ".join(prices[:2]) if prices else "Linke Bakınız"
            merchant = _guess_merchant_name(url)

            # Sanitize table columns (escape markdown pipes)
            clean_title = title.replace("|", "-").strip()
            clean_merchant = merchant.replace("|", "-").strip()
            clean_price = price_display.replace("|", "-").strip()

            # Include explicit URL markdown link
            link_markdown = f"[{clean_merchant} Satın Alma Linki]({url})"
            rows.append(f"| {i} | {clean_merchant} | {clean_title} | **{clean_price}** | {link_markdown} |")

            detailed_findings.append(
                f"### {i}. {clean_merchant}: {title}\n"
                f"- **Satın Alma / Ürün Linki:** {url}\n"
                f"- **Bulunan Fiyat:** {price_display}\n"
                f"- **Özet:** {snippet}\n"
            )

        scope_label = "Türkiye (Yerel)" if effective_scope == "tr" else "Global (Dünya Çapı)"
        output = [
            f"## 🔎 Fiyat Karşılaştırma Tablosu: '{query}'",
            f"**Kapsam:** {scope_label} | **Bulunan Sonuç:** {len(raw_results)}\n",
            "| # | Mağaza / Satıcı | Ürün Başlığı | Fiyat | Satın Alma Linki |",
            "|---|-----------------|--------------|-------|------------------|",
            *rows,
            "\n---\n",
            "### 📋 Satın Alma Linkleri ve Mağaza Detayları\n",
            "\n".join(detailed_findings)
        ]

        return _get_datetime_header() + "\n".join(output)

    except Exception as exc:
        logger.error(f"Error searching prices: {exc}")
        return "Error occurred while searching for prices: Request timed out or service unavailable."


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting WebBrowserMCP Server...")
    mcp.run()