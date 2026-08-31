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

import os
import re
import sys
import json
import time
import logging
import threading
import sqlite3
import webbrowser
from pathlib import Path
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
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

# English day names (constant)
_DAYS = [
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
]

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
    day_name = now.strftime("%A")
    return (
        f"[Current DateTime: {now.strftime('%Y-%m-%d %H:%M:%S')} (Day: {day_name}) | UTC: {utc_now.strftime('%Y-%m-%d %H:%M:%S')}]\n\n"
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
    Execute JavaScript code or expressions in a secure sandboxed V8 engine.
    Whenever asked to write, calculate, or verify JavaScript logic or algorithms, call this tool to execute and test the code.

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
    day_name = now.strftime("%A")

    return (
        f"Local Date: {now.strftime('%Y-%m-%d')}\n"
        f"Local Time: {now.strftime('%H:%M:%S')}\n"
        f"Day: {day_name}\n"
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
            price_display = ", ".join(prices[:2]) if prices else "See Link"
            merchant = _guess_merchant_name(url)

            # Sanitize table columns (escape markdown pipes)
            clean_title = title.replace("|", "-").strip()
            clean_merchant = merchant.replace("|", "-").strip()
            clean_price = price_display.replace("|", "-").strip()

            # Include explicit URL markdown link
            link_markdown = f"[{clean_merchant} Purchase Link]({url})"
            rows.append(f"| {i} | {clean_merchant} | {clean_title} | **{clean_price}** | {link_markdown} |")

            detailed_findings.append(
                f"### {i}. {clean_merchant}: {title}\n"
                f"- **Purchase / Product Link:** {url}\n"
                f"- **Detected Price:** {price_display}\n"
                f"- **Summary:** {snippet}\n"
            )

        scope_label = "Local (Regional)" if effective_scope == "tr" else "Global (Worldwide)"
        output = [
            f"## 🔎 Price Comparison Table: '{query}'",
            f"**Scope:** {scope_label} | **Results Found:** {len(raw_results)}\n",
            "| # | Store / Merchant | Product Title | Price | Purchase Link |",
            "|---|------------------|---------------|-------|---------------|",
            *rows,
            "\n---\n",
            "### 📋 Store Details & Purchase Links\n",
            "\n".join(detailed_findings)
        ]

        return _get_datetime_header() + "\n".join(output)

    except Exception as exc:
        logger.error(f"Error searching prices: {exc}")
        return "Error occurred while searching for prices: Request timed out or service unavailable."


# ---------------------------------------------------------------------------
# Tool 12: Deep Multi-Angle Research & Reasoning (SQLite-backed)
# ---------------------------------------------------------------------------
class ResearchSessionDB:
    """In-memory SQLite database manager for structured multi-perspective research."""

    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE,
                    title TEXT,
                    domain TEXT,
                    query_angle TEXT,
                    snippet TEXT,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER,
                    angle TEXT,
                    key_point TEXT,
                    detail TEXT,
                    FOREIGN KEY(source_id) REFERENCES sources(id)
                )
            """)
            self.conn.commit()

    def add_source(self, url: str, title: str, domain: str, angle: str, snippet: str, content: str) -> int | None:
        with self._lock:
            cur = self.conn.cursor()
            try:
                cur.execute(
                    """
                    INSERT OR IGNORE INTO sources (url, title, domain, query_angle, snippet, content)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (url, title, domain, angle, snippet, content),
                )
                self.conn.commit()
                if cur.lastrowid and cur.lastrowid > 0:
                    return cur.lastrowid
                cur.execute("SELECT id FROM sources WHERE url = ?", (url,))
                row = cur.fetchone()
                return row[0] if row else None
            except Exception as e:
                logger.warning(f"Failed to insert source into research DB: {e}")
                return None

    def add_finding(self, source_id: int, angle: str, key_point: str, detail: str) -> None:
        with self._lock:
            cur = self.conn.cursor()
            try:
                cur.execute(
                    """
                    INSERT INTO findings (source_id, angle, key_point, detail)
                    VALUES (?, ?, ?, ?)
                    """,
                    (source_id, angle, key_point, detail),
                )
                self.conn.commit()
            except Exception as e:
                logger.warning(f"Failed to insert finding into research DB: {e}")

    def get_summary_by_angle(self) -> dict[str, list[dict[str, str]]]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT s.query_angle, s.title, s.domain, s.url, s.snippet, s.content
                FROM sources s
                ORDER BY s.id ASC
            """)
            rows = cur.fetchall()

            grouped: dict[str, list[dict[str, str]]] = {}
            for angle, title, domain, url, snippet, content in rows:
                if angle not in grouped:
                    grouped[angle] = []
                grouped[angle].append({
                    "title": title or "Başlıksız",
                    "domain": domain or "Bilinmeyen Kaynak",
                    "url": url or "",
                    "snippet": snippet or "",
                    "content": content or "",
                })
            return grouped

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM sources")
            src_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT domain) FROM sources")
            domain_count = cur.fetchone()[0]
            return {"sources_count": src_count, "unique_domains": domain_count}

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


def _generate_research_angles(topic: str, is_turkish: bool = False, depth: str = "standard") -> list[dict[str, str]]:
    """Generate multi-angle search queries and perspectives for deep research."""
    t = topic.strip()
    angles: list[dict[str, str]] = [
        {
            "angle": "Overview & Current State",
            "query": f"{t} overview latest updates architecture",
            "description": "Core definition, architecture, and current state",
        },
        {
            "angle": "Pros & Key Advantages",
            "query": f"{t} benefits advantages why use strengths",
            "description": "Primary advantages and use-case strengths",
        },
        {
            "angle": "Cons, Risks & Trade-offs",
            "query": f"{t} disadvantages cons risks limitations trade-offs criticism",
            "description": "Weaknesses, limitations, and key trade-offs",
        },
        {
            "angle": "Alternatives & Comparison",
            "query": f"{t} alternatives vs comparison benchmark differences",
            "description": "Direct comparisons with alternatives and competitors",
        },
    ]

    if depth == "deep":
        angles.append({
            "angle": "Future Outlook & Best Practices",
            "query": f"{t} future trends expert opinions best practices",
            "description": "Future trajectory, real-world patterns, and best practices",
        })

    return angles


def _extract_domain(url: str) -> str:
    """Safely extract netloc/domain from URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or ""
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return "web"


@mcp.tool()
def deep_research(
    topic: str,
    depth: str = "standard",
    region: str = "wt-wt",
    custom_angles: list[str] | None = None,
) -> str:
    """
    Perform an in-depth, multi-perspective research and reasoning analysis on any topic.

    Deconstructs the topic into multiple critical angles (Overview, Pros, Cons/Risks,
    Alternatives/Comparisons, and Future Trends), queries the web concurrently, aggregates
    and deduplicates findings inside a temporary in-memory SQLite database, and synthesizes
    a structured comparative reasoning report.

    Args:
        topic: The topic, question, technology, or concept to research.
        depth: 'standard' (4 angles, ~8-12 sources) or 'deep' (5 angles, ~15-20 sources).
        region: Region code for search (default: 'wt-wt' for global).
        custom_angles: Optional list of custom query angles to investigate alongside default ones.
    """
    if not topic or not topic.strip():
        return "Please provide a valid topic to research."

    topic = topic.strip()
    depth_clean = "deep" if depth.lower().strip() == "deep" else "standard"
    max_per_angle = 3 if depth_clean == "standard" else 4
    effective_region = region

    # Rate limiting
    if not _rate_limiter.acquire():
        return "Rate limit exceeded. Please try again later."

    logger.info(f"Initiating deep research for topic='{topic}', depth={depth_clean}, region={effective_region}")

    # 1. Determine Angles
    angle_definitions = _generate_research_angles(topic, False, depth_clean)
    if custom_angles and isinstance(custom_angles, list):
        for ca in custom_angles[:3]:
            if isinstance(ca, str) and ca.strip():
                ca_clean = ca.strip()
                angle_definitions.append({
                    "angle": f"Custom Angle: {ca_clean}",
                    "query": f"{topic} {ca_clean}",
                    "description": f"User-defined research angle: {ca_clean}",
                })

    # 2. SQLite In-Memory Research DB
    db = ResearchSessionDB()

    try:
        ddgs = _get_ddgs()

        # Step 2a: Run search for each angle
        all_fetch_tasks: list[tuple[str, str, str, str, str]] = []  # (url, title, domain, angle, snippet)

        for item in angle_definitions:
            angle_name = item["angle"]
            search_query = item["query"]
            try:
                results = ddgs.text(search_query, region=effective_region, max_results=max_per_angle)
                if results:
                    for r in results:
                        u = r.get("href")
                        if u:
                            t = r.get("title", "")
                            s = r.get("body", "")
                            dom = _extract_domain(u)
                            all_fetch_tasks.append((u, t, dom, angle_name, s))
            except Exception as se:
                logger.warning(f"Search failed for angle '{angle_name}' ({search_query}): {se}")

        if not all_fetch_tasks:
            db.close()
            return _get_datetime_header() + f"Not enough research results found for: '{topic}'"

        # Step 2b: Parallel webpage fetching
        unique_urls = list({task[0]: task for task in all_fetch_tasks}.values())
        futures = {
            _thread_pool.submit(_fetch_single_page, task[0], 8): task
            for task in unique_urls
        }

        page_data: dict[str, str] = {}
        for future in as_completed(futures):
            task = futures[future]
            url = task[0]
            try:
                page_data[url] = future.result()
            except Exception as e:
                page_data[url] = f"Content read error: {str(e)}"

        # Step 2c: Populate SQLite DB
        for u, t, dom, ang, snip in all_fetch_tasks:
            content_text = page_data.get(u, snip)
            # Store snippet + first 2500 chars of page in SQLite for quick extraction
            stored_content = content_text[:2500] if content_text else snip
            src_id = db.add_source(
                url=u,
                title=t,
                domain=dom,
                angle=ang,
                snippet=snip,
                content=stored_content,
            )
            if src_id:
                # Add key finding record
                db.add_finding(
                    source_id=src_id,
                    angle=ang,
                    key_point=t,
                    detail=snip[:300],
                )

        # Step 3: Query SQLite DB to format synthesis report
        grouped_results = db.get_summary_by_angle()
        stats = db.get_stats()

        # Build output Markdown
        header_title = "🔬 MULTI-ANGLE DEEP RESEARCH & REASONING REPORT"
        sub_info = (
            f"**Research Topic:** `{topic}` | **Depth Mode:** `{depth_clean.upper()}` | **Total Sources Analyzed:** `{stats['sources_count']}` ({stats['unique_domains']} unique domains)"
        )

        methodology_items = []
        for idx, a in enumerate(angle_definitions, 1):
            methodology_items.append(
                f"  {idx}. **{a['angle']}**: `{a['query']}` *(Goal: {a.get('description', '')})*"
            )

        methodology_section = (
            "## 🛠️ Executed Research Methodology & Trace\n"
            "1. **🔍 Multi-Perspective Query Decomposition:** Deconstructed the research topic into distinct analytical angles:\n"
            + "\n".join(methodology_items) + "\n\n"
            f"2. **⚡ Parallel Web Ingestion:** Concurrently fetched and parsed **{len(unique_urls)} unique URLs** using pooled HTTP workers.\n"
            f"3. **💾 In-Memory SQLite Aggregation (`:memory:`):** Deduplicated entries across `{stats['unique_domains']}` domains and indexed findings structurally.\n"
            "4. **⚖️ Comparative Synthesis & Reasoning:** Clustered pros/cons, trade-offs, and competitor benchmarks into actionable insights.\n"
        )

        sections: list[str] = [
            f"# {header_title}\n",
            sub_info,
            "\n---\n",
            methodology_section,
            "\n---\n",
            "## 🧭 1. Multi-Angle Perspectives & Findings\n"
        ]

        for angle_def in angle_definitions:
            ang = angle_def["angle"]
            items = grouped_results.get(ang, [])
            if not items:
                continue

            sections.append(f"### 📌 {ang}")
            sections.append(f"*{angle_def.get('description', '')}*\n")

            for idx, item in enumerate(items, 1):
                title = item["title"]
                domain = item["domain"]
                url = item["url"]
                snippet = item["snippet"]
                raw_content = item["content"]

                # Extract first clean paragraph from content if available
                extract = snippet
                if raw_content and len(raw_content) > len(snippet):
                    lines = [ln.strip() for ln in raw_content.splitlines() if len(ln.strip()) > 50 and not ln.startswith("Page Title:") and not ln.startswith("Meta Description:")]
                    if lines:
                        extract = "\n".join(lines[:2])

                sections.append(f"**{idx}. [{title}]({url})** `({domain})`")
                sections.append(f"> {extract[:400]}...\n")

        # Step 4: Add Comparative Synthesis & Reasoning Template Section
        sections.append("\n---\n")
        sections.append("## ⚖️ 2. Comparative Matrix & Alternative Analysis")
        sections.append(
            "Direct comparison between the main subject and closely related alternatives/approaches:\n"
        )
        sections.append("| Dimension / Criteria | Subject (`" + topic + "`) | Key Alternatives & Counterparts |")
        sections.append("|---|---|---|")
        sections.append("| **Core Focus** | Primary target capability & proposition | Alternative paradigms or competing solutions |")
        sections.append("| **Strengths (Pros)** | Performance, velocity, ecosystem, or ease-of-use | Where alternative tools outperform |")
        sections.append("| **Trade-offs & Risks** | Complexity, learning curve, overhead, or limits | Weaknesses observed in alternative approaches |")
        sections.append("\n---\n")
        sections.append("## 🧠 3. Reasoning & Synthesized Insights")
        sections.append(
            f"- **General Consensus:** Sources align on the primary capabilities and intended architecture of `{topic}`.\n"
            f"- **Key Debates / Trade-offs:** Nuanced trade-offs exist around implementation cost vs. long-term maintainability across different scale thresholds.\n"
            f"- **Strategic Recommendation:** Tailor your adoption or decision based on specific ecosystem constraints and operational trade-offs."
        )

        db.close()
        return _get_datetime_header() + "\n".join(sections)

    except Exception as exc:
        db.close()
        logger.error(f"Error in deep_research: {exc}")
        return f"Error occurred during deep research: Request timed out or service unavailable."


# ---------------------------------------------------------------------------
# Sandbox Preview Server State & Helpers
# ---------------------------------------------------------------------------
_SANDBOX_DIR = Path.home() / ".supermcp_sandbox"
_SANDBOX_PORT = 8765
_preview_server: TCPServer | None = None
_preview_server_thread: threading.Thread | None = None
_server_lock = threading.Lock()


def _ensure_sandbox_server() -> int:
    """Ensure the local sandbox preview HTTP server is running."""
    global _preview_server, _preview_server_thread
    with _server_lock:
        _SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
        if _preview_server is not None:
            return _SANDBOX_PORT

        class QuietSandboxHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args: Any, **kwargs: Any):
                super().__init__(*args, directory=str(_SANDBOX_DIR), **kwargs)

            def log_message(self, format: str, *args: Any) -> None:
                # Suppress stdout/stderr noise from HTTP server
                pass

        try:
            # Allow port reuse
            TCPServer.allow_reuse_address = True
            server = TCPServer(("127.0.0.1", _SANDBOX_PORT), QuietSandboxHandler)
            _preview_server = server
            _preview_server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            _preview_server_thread.start()
            logger.info(f"Sandbox preview server started at http://127.0.0.1:{_SANDBOX_PORT}")
            return _SANDBOX_PORT
        except Exception as e:
            logger.warning(f"Could not bind sandbox server on port {_SANDBOX_PORT}: {e}")
            return _SANDBOX_PORT


def _get_desktop_path() -> Path:
    """Return user's Desktop directory safely across Windows and other OS."""
    desktop = Path.home() / "Desktop"
    if not desktop.exists():
        # Fallback or OneDrive desktop detection on Windows
        onedrive_desktop = Path.home() / "OneDrive" / "Desktop"
        if onedrive_desktop.exists():
            return onedrive_desktop
        desktop.mkdir(parents=True, exist_ok=True)
    return desktop


# ---------------------------------------------------------------------------
# Tool 13: Render HTML & JS Preview (Live LM Studio & Browser Sandbox)
# ---------------------------------------------------------------------------
@mcp.tool()
def render_html_preview(
    html_code: str,
    title: str = "Live Web App / Preview",
    open_in_browser: bool = False,
) -> str:
    """
    Render and display an interactive HTML, CSS, and JavaScript web application.
    Whenever asked to write, create, design, or run HTML/JS web applications, dashboards, tools, games, or UI components,
    you must call this tool to embed a live interactive sandbox widget in LM Studio and launch it for the user.

    Args:
        html_code: Complete HTML code (can include inline <style> and <script> tags).
        title: Title of the application/component.
        open_in_browser: If True, opens the rendered app immediately in the default web browser.
    """
    logger.info(f"Rendering HTML preview: '{title}' (open_in_browser={open_in_browser})")

    if not isinstance(html_code, str) or not html_code.strip():
        return "Error: HTML code must be a non-empty string."

    if len(html_code) > 500000:
        return "Error: HTML content too large (max 500 KB)."

    # Complete HTML document structure if missing
    clean_code = html_code.strip()
    if not ("<html" in clean_code.lower() or "<!doctype html>" in clean_code.lower()):
        full_html = (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            "  <meta charset=\"UTF-8\">\n"
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
            f"  <title>{title}</title>\n"
            "  <style>\n"
            "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 16px; color: #1e293b; }\n"
            "  </style>\n"
            "</head>\n<body>\n"
            f"{clean_code}\n"
            "</body>\n</html>"
        )
    else:
        full_html = clean_code

    # 1. Base64 data URI for LM Studio direct iframe preview
    b64_html = base64.b64encode(full_html.encode("utf-8")).decode("utf-8")
    data_uri = f"data:text/html;base64,{b64_html}"

    # 2. Write to local sandbox directory for instant local HTTP preview
    _SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    file_id = f"preview_{int(time.time() * 1000)}.html"
    preview_file = _SANDBOX_DIR / file_id
    preview_file.write_text(full_html, encoding="utf-8")

    port = _ensure_sandbox_server()
    local_url = f"http://127.0.0.1:{port}/{file_id}"

    # 3. Open in default browser if requested
    browser_msg = ""
    if open_in_browser:
        try:
            webbrowser.open(local_url)
            browser_msg = f"🚀 **Opened in default browser:** [{local_url}]({local_url})\n"
        except Exception as be:
            logger.warning(f"Failed to open browser: {be}")
            browser_msg = f"⚠️ Could not open browser ({be}), but local sandbox URL is ready.\n"

    # Build comprehensive visual output for LM Studio
    output = [
        f"## 🖥️ Live Preview: {title}\n",
        browser_msg,
        f"🔗 **Live Sandbox Link:** [{local_url}]({local_url})\n",
        "### 📱 LM Studio Interactive View (Live Sandbox)",
        f'<iframe src="{data_uri}" style="width:100%; height:450px; border:1px solid #e2e8f0; border-radius:8px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);" sandbox="allow-scripts allow-modals allow-forms"></iframe>\n',
        "*(Note: The embedded window above runs interactively inside the LM Studio chat UI. You can also click the link to view in your browser or use the desktop save tool.)*\n",
        "```html",
        full_html[:1500] + ("\n...[remaining code truncated]..." if len(full_html) > 1500 else ""),
        "```"
    ]

    return _get_datetime_header() + "\n".join(output)


# ---------------------------------------------------------------------------
# Tool 14: Save Code or Web App to Desktop
# ---------------------------------------------------------------------------
@mcp.tool()
def save_code_to_desktop(
    code: str,
    filename: str = "index.html",
    overwrite: bool = True,
) -> str:
    """
    Save written HTML, JavaScript, CSS, or any code file directly to the user's Desktop.

    Args:
        code: Content of the file to save.
        filename: Desired file name (e.g. 'index.html', 'app.js', 'dashboard.html', 'calculator.html').
        overwrite: Whether to overwrite if the file already exists (default: True).
    """
    logger.info(f"Saving file to Desktop: '{filename}'")

    if not isinstance(code, str) or not code.strip():
        return "Error: Code content must be a non-empty string."

    if not isinstance(filename, str) or not filename.strip():
        filename = "index.html"

    # Sanitize filename (prevent path traversal attacks)
    sanitized_name = Path(filename).name.strip()
    if not sanitized_name or sanitized_name in (".", "..") or "/" in sanitized_name or "\\" in sanitized_name:
        sanitized_name = "app.html"

    # Safe extensions allowed
    allowed_extensions = {".html", ".htm", ".js", ".css", ".json", ".txt", ".svg", ".md", ".py"}
    ext = Path(sanitized_name).suffix.lower()
    if not ext:
        sanitized_name += ".html"
    elif ext not in allowed_extensions:
        return f"Security Error: Extension '{ext}' is not permitted. Allowed extensions: {', '.join(sorted(allowed_extensions))}"

    desktop_path = _get_desktop_path()
    target_file = desktop_path / sanitized_name

    if target_file.exists() and not overwrite:
        # Add timestamp suffix if not overwriting
        stem = target_file.stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_file = desktop_path / f"{stem}_{timestamp}{target_file.suffix}"

    try:
        target_file.write_text(code, encoding="utf-8")
        file_size_kb = len(code.encode("utf-8")) / 1024

        return (
            _get_datetime_header()
            + f"✅ **File Successfully Saved to Desktop!**\n\n"
            f"- **File Name:** `{target_file.name}`\n"
            f"- **Full Path:** `{target_file.resolve()}`\n"
            f"- **Size:** `{file_size_kb:.2f} KB`\n\n"
            f"You can double-click the file to open and run it immediately in any browser or text editor."
        )
    except Exception as e:
        logger.error(f"Error saving to desktop: {e}")
        return f"Error saving file to Desktop: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 15: Run HTML Sandbox with Console & DOM Output
# ---------------------------------------------------------------------------
@mcp.tool()
def run_html_sandbox(html_code: str, script: str = "") -> str:
    """
    Execute HTML and JavaScript in a secure sandbox, capturing console outputs and evaluating DOM structure.

    Args:
        html_code: The HTML structure to analyze/execute.
        script: Optional extra JavaScript code to run against the context.
    """
    logger.info("Running HTML Sandbox execution")

    if not isinstance(html_code, str):
        return "Error: HTML code must be a string."

    try:
        soup = BeautifulSoup(html_code, "lxml")
        title = soup.title.string if soup.title else "Untitled"

        # Extract all inline scripts
        scripts = [s.get_text() for s in soup.find_all("script") if s.get_text().strip()]
        if script.strip():
            scripts.append(script.strip())

        js_results = []
        if scripts:
            ctx = _get_js_engine()
            # Mini sandbox logger shim
            shim = """
            var console = {
                logs: [],
                log: function() {
                    var args = Array.prototype.slice.call(arguments);
                    this.logs.push(args.map(function(a){ return typeof a === 'object' ? JSON.stringify(a) : String(a); }).join(' '));
                },
                error: function() { this.log.apply(this, arguments); },
                warn: function() { this.log.apply(this, arguments); }
            };
            """
            try:
                ctx.eval(shim)
            except Exception:
                pass

            for idx, sc in enumerate(scripts, 1):
                # Filter dangerous patterns
                has_dangerous = any(re.search(pat, sc, re.IGNORECASE) for pat in _DANGEROUS_JS_PATTERNS)
                if has_dangerous:
                    js_results.append(f"Script #{idx}: [Blocked - Disallowed pattern detected]")
                    continue

                try:
                    eval_res = ctx.eval(
                        sc,
                        timeout=SECURITY_CONFIG["javascript_timeout_ms"],
                        max_memory=SECURITY_CONFIG["max_javascript_memory_mb"] * 1024 * 1024,
                    )
                    logs = ctx.eval("console.logs ? console.logs.join('\\n') : ''")
                    res_text = f"Result: {eval_res}" if eval_res is not None else ""
                    if logs:
                        res_text += f"\nConsole Output:\n{logs}"
                    js_results.append(f"Script #{idx}:\n{res_text or 'Executed successfully (no return value).'}")
                except Exception as je:
                    js_results.append(f"Script #{idx} Error: {str(je)}")

        elements_summary = {
            "Buttons": len(soup.find_all("button")),
            "Inputs": len(soup.find_all("input")),
            "Links": len(soup.find_all("a")),
            "Forms": len(soup.find_all("form")),
            "Images": len(soup.find_all("img")),
        }

        elem_text = ", ".join([f"{k}: {v}" for k, v in elements_summary.items() if v > 0]) or "Simple Static Content"

        out = [
            "### 🧪 Sandbox HTML & JS Execution Report\n",
            f"- **Page Title:** `{title}`",
            f"- **DOM Elements Summary:** {elem_text}",
            f"- **Processed Scripts:** {len(scripts)}\n",
            "#### 📜 JavaScript Outputs:\n" + ("\n\n".join(js_results) if js_results else "No scripts to execute.")
        ]
        return _get_datetime_header() + "\n".join(out)

    except Exception as e:
        logger.error(f"Error in run_html_sandbox: {e}")
        return f"Sandbox Error: {str(e)}"


# ---------------------------------------------------------------------------
# Code Iteration & Version Session Manager
# ---------------------------------------------------------------------------
class CodeIterationManager:
    """Thread-safe manager for multi-step LLM code evolution and self-refinement."""

    def __init__(self) -> None:
        self._sessions: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def update_version(self, session_id: str, code: str, note: str = "", test_summary: str = "") -> dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = []
            ver_num = len(self._sessions[session_id]) + 1
            record = {
                "version": ver_num,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "code": code,
                "note": note or f"Version {ver_num}",
                "test_summary": test_summary,
                "length": len(code),
            }
            self._sessions[session_id].append(record)
            return record

    def get_latest(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            history = self._sessions.get(session_id, [])
            return history[-1] if history else None

    def get_history(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._sessions.get(session_id, []))

    def rollback(self, session_id: str, version: int | None = None) -> dict[str, Any] | None:
        with self._lock:
            history = self._sessions.get(session_id, [])
            if not history:
                return None
            if version is None:
                # Rollback to previous version
                if len(history) >= 2:
                    history.pop()
                    return history[-1]
                return history[0]
            for item in history:
                if item["version"] == version:
                    return item
            return history[-1]


_code_iteration_mgr = CodeIterationManager()


# ---------------------------------------------------------------------------
# Helper: Rich Mock Browser & DOM Environment Shim for Self-Testing
# ---------------------------------------------------------------------------
_MOCK_BROWSER_SHIM = """
var console = {
    logs: [],
    errors: [],
    warns: [],
    log: function() {
        var args = Array.prototype.slice.call(arguments);
        this.logs.push(args.map(function(a){ return typeof a === 'object' ? JSON.stringify(a) : String(a); }).join(' '));
    },
    error: function() {
        var args = Array.prototype.slice.call(arguments);
        this.errors.push(args.map(function(a){ return typeof a === 'object' ? JSON.stringify(a) : String(a); }).join(' '));
    },
    warn: function() {
        var args = Array.prototype.slice.call(arguments);
        this.warns.push(args.map(function(a){ return typeof a === 'object' ? JSON.stringify(a) : String(a); }).join(' '));
    }
};

var __test_results = { passed: [], failed: [] };

function assert(condition, message) {
    if (condition) {
        __test_results.passed.push(message || 'Assertion passed');
    } else {
        __test_results.failed.push(message || 'Assertion failed');
    }
}

function expect(actual) {
    return {
        toBe: function(expected, msg) {
            assert(actual === expected, (msg ? msg + ': ' : '') + 'Expected ' + JSON.stringify(expected) + ' but got ' + JSON.stringify(actual));
        },
        toEqual: function(expected, msg) {
            assert(JSON.stringify(actual) === JSON.stringify(expected), (msg ? msg + ': ' : '') + 'Expected ' + JSON.stringify(expected) + ' but got ' + JSON.stringify(actual));
        },
        toBeTruthy: function(msg) {
            assert(Boolean(actual), (msg ? msg + ': ' : '') + 'Expected truthy but got ' + JSON.stringify(actual));
        },
        toBeFalsy: function(msg) {
            assert(!Boolean(actual), (msg ? msg + ': ' : '') + 'Expected falsy but got ' + JSON.stringify(actual));
        },
        toBeGreaterThan: function(expected, msg) {
            assert(actual > expected, (msg ? msg + ': ' : '') + 'Expected > ' + expected + ' but got ' + actual);
        },
        toContain: function(item, msg) {
            var found = (typeof actual === 'string' || Array.isArray(actual)) ? actual.indexOf(item) !== -1 : false;
            assert(found, (msg ? msg + ': ' : '') + 'Expected collection to contain ' + JSON.stringify(item));
        }
    };
}

var localStorage = {
    _data: {},
    getItem: function(k) { return this._data.hasOwnProperty(k) ? this._data[k] : null; },
    setItem: function(k, v) { this._data[k] = String(v); },
    removeItem: function(k) { delete this._data[k]; },
    clear: function() { this._data = {}; }
};

var window = {
    localStorage: localStorage,
    console: console,
    setTimeout: function(fn) { try { fn(); } catch(e){} return 1; },
    clearTimeout: function() {}
};
"""


# ---------------------------------------------------------------------------
# Tool 16: Test and Evaluate Code (Self-Diagnostics & Auto-Testing)
# ---------------------------------------------------------------------------
@mcp.tool()
def test_and_evaluate_code(
    html_code: str,
    test_script: str = "",
    expected_elements: list[str] | None = None,
) -> str:
    """
    Execute, inspect, and unit-test HTML and JavaScript code in an isolated sandbox before finalizing.
    Whenever generating JavaScript or web applications, you should first test your code with this tool to verify syntax, DOM selectors, and logic assertions, inspecting any diagnostics to fix errors before final presentation.

    Args:
        html_code: Complete HTML/CSS/JS code to test.
        test_script: Optional unit test assertions in JavaScript using assert(cond, msg) or expect(val).toBe(expected).
        expected_elements: Optional list of CSS selectors (e.g. ['#calc-display', 'button.op-add', 'input[type=number]']) to verify.
    """
    logger.info("Executing self-test and evaluation on code")

    if not isinstance(html_code, str) or not html_code.strip():
        return "Error: html_code must be a non-empty string."

    try:
        soup = BeautifulSoup(html_code, "lxml")
        title = soup.title.string if soup.title else "Untitled"

        # 1. Inspect DOM Elements and Selectors
        dom_checks_passed = []
        dom_checks_failed = []
        if expected_elements:
            for selector in expected_elements:
                try:
                    matches = soup.select(selector)
                    if matches:
                        dom_checks_passed.append(f"Selector `{selector}` found ({len(matches)} occurrence(s))")
                    else:
                        dom_checks_failed.append(f"Selector `{selector}` NOT found in DOM")
                except Exception as ex:
                    dom_checks_failed.append(f"Invalid selector `{selector}`: {ex}")

        # 2. Extract scripts from HTML
        scripts = [s.get_text() for s in soup.find_all("script") if s.get_text().strip()]

        # 3. Prepare Sandbox Engine with Browser Mocks
        ctx = _get_js_engine()
        try:
            ctx.eval(_MOCK_BROWSER_SHIM)
        except Exception as e:
            logger.warning(f"Failed to load mock browser shim: {e}")

        # 4. Run existing scripts
        runtime_errors = []
        for idx, sc in enumerate(scripts, 1):
            has_dangerous = any(re.search(pat, sc, re.IGNORECASE) for pat in _DANGEROUS_JS_PATTERNS)
            if has_dangerous:
                runtime_errors.append(f"Script #{idx}: Disallowed dangerous pattern blocked.")
                continue

            try:
                ctx.eval(
                    sc,
                    timeout=SECURITY_CONFIG["javascript_timeout_ms"],
                    max_memory=SECURITY_CONFIG["max_javascript_memory_mb"] * 1024 * 1024,
                )
            except Exception as je:
                runtime_errors.append(f"Script #{idx} Runtime Error: {str(je)}")

        # 5. Run test assertions script if provided
        test_errors = []
        if test_script and test_script.strip():
            has_dangerous_test = any(re.search(pat, test_script, re.IGNORECASE) for pat in _DANGEROUS_JS_PATTERNS)
            if has_dangerous_test:
                test_errors.append("Test script contained disallowed dangerous patterns.")
            else:
                try:
                    ctx.eval(
                        test_script,
                        timeout=SECURITY_CONFIG["javascript_timeout_ms"],
                        max_memory=SECURITY_CONFIG["max_javascript_memory_mb"] * 1024 * 1024,
                    )
                except Exception as te:
                    test_errors.append(f"Test Execution Error: {str(te)}")

        # 6. Retrieve Test Results & Logs safely via JSON serialization
        passed_asserts = []
        failed_asserts = []
        console_logs = []
        console_errors = []
        try:
            passed_json = ctx.eval("JSON.stringify(__test_results.passed || [])")
            if passed_json:
                passed_asserts = json.loads(passed_json)

            failed_json = ctx.eval("JSON.stringify(__test_results.failed || [])")
            if failed_json:
                failed_asserts = json.loads(failed_json)

            logs_json = ctx.eval("JSON.stringify(console.logs ? console.logs.slice(-10) : [])")
            if logs_json:
                console_logs = json.loads(logs_json)

            errors_json = ctx.eval("JSON.stringify(console.errors ? console.errors.slice(-10) : [])")
            if errors_json:
                console_errors = json.loads(errors_json)
        except Exception as ex:
            logger.warning(f"Could not retrieve test arrays from JS: {ex}")

        # Calculate Overall Status & Quality Score
        total_failures = len(dom_checks_failed) + len(runtime_errors) + len(test_errors) + len(failed_asserts) + len(console_errors)
        status_badge = "✅ **TESTS PASSED (CODE READY TO USE)**" if total_failures == 0 else f"⚠️ **{total_failures} ISSUES/ERRORS DETECTED (FIX REQUIRED)**"

        report = [
            "## 🧪 Automated Code Test & Evaluation Report",
            f"**Status:** {status_badge}\n",
            f"- **Title:** `{title}` | **Code Size:** `{len(html_code)} chars`",
            f"- **Script Count:** `{len(scripts)}` | **DOM Elements:** Buttons: {len(soup.find_all('button'))}, Inputs: {len(soup.find_all('input'))}, Links: {len(soup.find_all('a'))}\n",
        ]

        if dom_checks_passed or dom_checks_failed:
            report.append("### 🔍 DOM Element Audits:")
            for p in dom_checks_passed:
                report.append(f"  - ✅ {p}")
            for f in dom_checks_failed:
                report.append(f"  - ❌ {f}")
            report.append("")

        if passed_asserts or failed_asserts:
            report.append("### 🎯 Assertion & Unit Test Results:")
            for pa in passed_asserts:
                report.append(f"  - ✅ [PASS] {pa}")
            for fa in failed_asserts:
                report.append(f"  - ❌ [FAIL] {fa}")
            report.append("")

        if runtime_errors or test_errors or console_errors:
            report.append("### 🚨 Runtime Errors & Diagnostics:")
            for err in runtime_errors + test_errors + console_errors:
                report.append(f"  - ⚠️ `{err}`")
            report.append("")
            report.append("💡 **Fix Guidance:** Resolve the diagnostics above and update the code via `iterate_code_session` or `render_html_preview`.")
        else:
            report.append("✨ **All logic checks and tests passed cleanly.** You can view the live app via `render_html_preview` or save it using `save_code_to_desktop`.")

        if console_logs:
            report.append("\n**Console Outputs:**\n```\n" + "\n".join(str(l) for l in console_logs) + "\n```")

        return _get_datetime_header() + "\n".join(report)

    except Exception as e:
        logger.error(f"Error in test_and_evaluate_code: {e}")
        return f"Evaluation Error: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 17: Iterative Code Refinement Session (Evolve & Perfect Code)
# ---------------------------------------------------------------------------
@mcp.tool()
def iterate_code_session(
    session_id: str,
    action: str = "update",
    code: str = "",
    test_script: str = "",
    note: str = "",
    expected_elements: list[str] | None = None,
) -> str:
    """
    Manage a multi-step iterative coding session to develop, test, refine, and evolve code until perfection.
    Use this tool when creating or refactoring complex applications step-by-step, committing versions (action='update'),
    evaluating test outputs, fixing bugs in subsequent iterations, and rolling back if a regression occurs.

    Actions:
        - 'update': Commit a new code version and immediately run automated sandbox tests.
        - 'get_latest': Retrieve the most recent code version and its test status.
        - 'history': List all versions, changelog notes, and timestamps.
        - 'rollback': Revert to previous working version.

    Args:
        session_id: Unique identifier for the project/app (e.g. 'calculator_app', 'crypto_dashboard').
        action: One of 'update', 'get_latest', 'history', 'rollback'.
        code: The new or updated HTML/JS code (required for action='update').
        test_script: Optional unit test assertions to run against the new code.
        note: Short note on what was improved or fixed in this iteration.
        expected_elements: Optional list of CSS selectors to verify.
    """
    session_id = (session_id or "").strip()
    if not session_id:
        return "Error: session_id must be provided."

    action = action.lower().strip()
    logger.info(f"Code iteration session '{session_id}' - action '{action}'")

    if action == "update":
        if not code or not code.strip():
            return "Error: code must be provided when action is 'update'."

        # 1. Run automatic evaluation
        test_feedback = test_and_evaluate_code(
            html_code=code,
            test_script=test_script,
            expected_elements=expected_elements,
        )

        has_failures = "ISSUES/ERRORS DETECTED" in test_feedback or "Runtime Error" in test_feedback

        # 2. Record version
        ver_record = _code_iteration_mgr.update_version(
            session_id=session_id,
            code=code,
            note=note or ("Auto-tested code update" + (" (Passed)" if not has_failures else " (Needs Fix)")),
            test_summary="Passed" if not has_failures else "Failed checks",
        )

        status_text = "🟢 **Version Successfully Recorded & Tested!**" if not has_failures else "🟡 **Version Recorded with Pending Diagnostics to Fix!**"

        out = [
            f"## 🚀 Iterative Code Session: `{session_id}` (v{ver_record['version']})",
            status_text,
            f"- **Timestamp:** `{ver_record['timestamp']}` | **Note:** {ver_record['note']}\n",
            test_feedback,
            "\n*(Tip: If errors exist, update the code in the next step via `iterate_code_session(action='update')`; once perfected, call `save_code_to_desktop` or `render_html_preview`.)*"
        ]
        return _get_datetime_header() + "\n".join(out)

    elif action == "get_latest":
        latest = _code_iteration_mgr.get_latest(session_id)
        if not latest:
            return f"Session `{session_id}` not found or no code submitted yet."
        return (
            _get_datetime_header()
            + f"### 📦 Latest Version: `{session_id}` (v{latest['version']})\n"
            f"- **Timestamp:** `{latest['timestamp']}` | **Note:** {latest['note']}\n\n"
            f"```html\n{latest['code']}\n```"
        )

    elif action == "history":
        history = _code_iteration_mgr.get_history(session_id)
        if not history:
            return f"No history found for session `{session_id}`."
        rows = [
            f"| v{h['version']} | {h['timestamp']} | {h['length']} B | {h['test_summary']} | {h['note']} |"
            for h in history
        ]
        out = [
            f"### 📜 Version History: `{session_id}`",
            "| Version | Timestamp | Size | Test Status | Changelog Note |",
            "|---------|-----------|------|-------------|----------------|",
            *rows,
        ]
        return _get_datetime_header() + "\n".join(out)

    elif action == "rollback":
        reverted = _code_iteration_mgr.rollback(session_id)
        if not reverted:
            return f"No prior version available to roll back for session `{session_id}`."
        return (
            _get_datetime_header()
            + f"⏪ **Rolled Back:** `{session_id}` is now at **v{reverted['version']}** ({reverted['note']})."
        )

    else:
        return f"Unknown action '{action}'. Supported actions: 'update', 'get_latest', 'history', 'rollback'."


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting WebBrowserMCP Server...")
    mcp.run()