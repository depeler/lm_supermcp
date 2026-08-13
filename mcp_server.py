import re
import sys
import logging
from datetime import datetime, timezone
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

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
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        })
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
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
_ddgs_client: DDGS | None = None

def _get_ddgs() -> DDGS:
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
# Tool 1: Web Search
# ---------------------------------------------------------------------------
@mcp.tool(description=f"""
CRITICAL: Use this tool ALWAYS when you need to search the internet for current events, real-time information, news, or facts you do not know.
This searches the web AND automatically reads all result pages in parallel, giving you full content immediately.
[SYSTEM NOTE: Today's date is {_TODAY}. Keep this in mind when searching for recent events.]

Args:
    query: The search query string. Keep it concise for better results.
    max_results: Maximum number of results to return (default 5).
    region: Region code for localized results (default "tr-tr").
""")
def search_web(query: str, max_results: int = 5, region: str = "tr-tr") -> str:
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
            except Exception as e:
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

        return "\n\n" + "=" * 60 + "\n\n".join(output_parts)
    except Exception as e:
        logger.error(f"Error searching web: {e}")
        return f"Error occurred while searching: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 2: News Search
# ---------------------------------------------------------------------------
@mcp.tool(description=f"""
CRITICAL: Use this tool when the user asks about recent news, breaking events, or current affairs.
This searches specifically in news sources for the most up-to-date articles.
[SYSTEM NOTE: Today's date is {_TODAY}.]

Args:
    query: The news search query string.
    max_results: Maximum number of news articles to return (default 5).
    region: Region code for localized news (default "tr-tr").
""")
def search_news(query: str, max_results: int = 5, region: str = "tr-tr") -> str:
    logger.info(f"Searching news for: {query} (region={region})")
    try:
        ddgs = _get_ddgs()
        raw_results = ddgs.news(query, region=region, max_results=max_results)

        if not raw_results:
            return "No news articles found."

        results = [
            f"Title: {r.get('title')}\nSource: {r.get('source')}\nDate: {r.get('date')}\nURL: {r.get('url')}\nSnippet: {r.get('body')}"
            for r in raw_results
        ]
        return "\n\n---\n\n".join(results)
    except Exception as e:
        logger.error(f"Error searching news: {e}")
        return f"Error occurred while searching news: {str(e)}"


# ---------------------------------------------------------------------------
# Helper: Fetch a single page (used by both single and batch tools)
# ---------------------------------------------------------------------------
def _fetch_single_page(url: str) -> str:
    """Fetch and extract clean text from a single URL. Internal helper."""
    try:
        session = _get_http_session()
        response = session.get(url, timeout=15)
        response.raise_for_status()

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
        logger.error(f"Error reading {url}: {e}")
        return f"Error reading {url}: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 3: Read Webpage (single)
# ---------------------------------------------------------------------------
@mcp.tool()
def read_webpage(url: str) -> str:
    """
    CRITICAL: Use this tool to read the full text content of a SINGLE webpage URL.
    If you need to read multiple pages at once, use read_multiple_webpages instead.

    Args:
        url: The exact URL of the webpage to read.
    """
    logger.info(f"Reading webpage: {url}")
    return _fetch_single_page(url)


# ---------------------------------------------------------------------------
# Tool 4: Read Multiple Webpages (concurrent)
# ---------------------------------------------------------------------------
@mcp.tool()
def read_multiple_webpages(urls: list[str]) -> str:
    """
    CRITICAL: Use this tool to read MULTIPLE webpages AT THE SAME TIME in parallel.
    This is much faster than calling read_webpage one by one.
    Use this after search_web or search_news when you want to read several result pages at once.

    Args:
        urls: A list of URLs to read concurrently. Example: ["https://example.com", "https://example2.com"]
    """
    logger.info(f"Reading {len(urls)} webpages concurrently")

    results: dict[str, str] = {}
    futures = {_thread_pool.submit(_fetch_single_page, url): url for url in urls}

    for future in as_completed(futures):
        url = futures[future]
        try:
            results[url] = future.result()
        except Exception as e:
            results[url] = f"Error reading {url}: {str(e)}"

    # Build output in original URL order
    output_parts = []
    for i, url in enumerate(urls, 1):
        output_parts.append(f"=== PAGE {i}: {url} ===\n\n{results.get(url, 'No data')}")

    return "\n\n{'='*60}\n\n".join(output_parts)


# ---------------------------------------------------------------------------
# Tool 5: Search and Read (all-in-one)
# ---------------------------------------------------------------------------
@mcp.tool(description=f"""
CRITICAL: Use this tool for comprehensive research. It searches the web AND reads the top result pages in parallel, all in one step.
[SYSTEM NOTE: Today's date is {_TODAY}.]

Args:
    query: The search query string.
    max_pages: How many of the top search results to read in full (default 3, max 5).
    region: Region code for localized results (default "tr-tr").
""")
def search_and_read(query: str, max_pages: int = 3, region: str = "tr-tr") -> str:
    logger.info(f"Search-and-read for: {query} (top {max_pages} pages)")
    max_pages = min(max_pages, 5)  # Safety cap

    try:
        # Step 1: Search
        ddgs = _get_ddgs()
        search_results = ddgs.text(query, region=region, max_results=max_pages)

        if not search_results:
            return "No search results found."

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

        return "\n\n{'='*60}\n\n".join(output_parts)
    except Exception as e:
        logger.error(f"Error in search_and_read: {e}")
        return f"Error: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 7: Read PDF File
# ---------------------------------------------------------------------------
@ mcp.tool(description=f"""
Use this tool to read and extract text content from a PDF file.

Args:
    file_path: The path to the PDF file to read. Can be local or remote URL.
""")
def read_pdf(file_path: str) -> str:
    """
    Extract text content from a PDF file using PyPDF2.

    Args:
        file_path: Path to the PDF file (local file path or URL that returns a PDF)
    
    Returns:
        Extracted text content from the PDF, or error message if failed.
    """
    logger.info(f"Reading PDF file: {file_path}")
    try:
        # Try to fetch PDF as bytes
        session = _get_http_session()
        response = session.get(file_path, timeout=15)
        response.raise_for_status()
        
        # Check content type
        if "application/pdf" not in response.headers.get("Content-Type", ""):
            return f"Error: Content-Type is '{response.headers.get('Content-Type', '')}', expected 'application/pdf'"
        
        pdf_bytes = response.content
        
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
            except Exception as e:
                all_text.append(f"--- Page {i + 1} ---\nError: {str(e)}\n")
        
        if not all_text:
            return "No text could be extracted from the PDF."
        
        content = "".join(all_text)
        if len(content) > _MAX_CONTENT_LENGTH:
            content = content[:_MAX_CONTENT_LENGTH] + "\n\n...[Content truncated due to length]..."
        
        return f"PDF Content ({len(reader.pages)} pages):\n\n{content}"
    except Exception as e:
        logger.error(f"Error reading PDF: {e}")
        return f"Error reading PDF file: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 8: Execute JavaScript (renamed from Tool 4/6 to fix numbering)
# ---------------------------------------------------------------------------
@mcp.tool()
def execute_javascript(code: str) -> str:
    """
    CRITICAL: Use this tool to execute JavaScript code. Useful for math calculations, data processing, algorithms, or generating specific text.
    The code runs in an isolated V8 JavaScript engine environment with a 5-second timeout and 64 MB memory limit.

    Args:
        code: The JavaScript code string to execute. It must return a value or evaluate to an expression.
    """
    logger.info("Executing JavaScript code")
    try:
        ctx = _get_js_engine()
        # 5 second timeout, 64 MB memory limit for safety
        result = ctx.eval(code, timeout=5000, max_memory=64 * 1024 * 1024)
        return str(result)
    except Exception as e:
        logger.error(f"Error executing JavaScript: {e}")
        return f"JavaScript Execution Error: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 10: Get Current Date and Time
# ---------------------------------------------------------------------------
@ mcp.tool()
def get_current_datetime() -> str:
    """
    Returns the current date, time, and day of the week.
    Use this when the user asks about today's date, the current time, or when you need temporal context for searches.
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
# Tool 6: Translate Text
# ---------------------------------------------------------------------------
@mcp.tool()
def translate_text(text: str, target_language: str = "tr", source_language: str = "auto") -> str:
    """
    Translate text between languages. Useful when search results are in a foreign language and need to be translated for the user.

    Args:
        text: The text to translate.
        target_language: Target language code (default "tr" for Turkish). Examples: "en", "de", "fr", "es", "ar", "ja".
        source_language: Source language code (default "auto" for auto-detection).
    """
    logger.info(f"Translating text to {target_language}")
    try:
        translator = _get_translator(source_language, target_language)

        # deep-translator has a 5000 char limit per call, split if needed
        if len(text) > 4500:
            chunks = [text[i : i + 4500] for i in range(0, len(text), 4500)]
            translated_chunks = [translator.translate(chunk) for chunk in chunks]
            return "".join(translated_chunks)

        return translator.translate(text)
    except Exception as e:
        logger.error(f"Error translating text: {e}")
        return f"Translation Error: {str(e)}"


# ---------------------------------------------------------------------------
# Tool 9: Search Images
# ---------------------------------------------------------------------------
@mcp.tool(description=f"""
CRITICAL: Use this tool when the user asks to see images, photos, or pictures of something.
This searches the web for images and returns them directly into your vision context.
[SYSTEM NOTE: Today's date is {_TODAY}.]

Args:
    query: The image search query.
    max_results: Number of images to fetch (default 2, max 4).
    region: Region code (default "tr-tr").
""")
def search_images(query: str, max_results: int = 2, region: str = "tr-tr") -> list:
    logger.info(f"Searching images for: {query}")
    max_results = min(max_results, 4)
    try:
        ddgs = _get_ddgs()
        raw_results = ddgs.images(query, region=region, max_results=max_results)
        
        if not raw_results:
            return [types.TextContent(type="text", text="No images found.")]
            
        content_blocks = []
        content_blocks.append(types.TextContent(type="text", text=f"Found {len(raw_results)} images for '{query}':\n"))
        
        session = _get_http_session()
        for i, r in enumerate(raw_results, 1):
            title = r.get("title", "Unknown")
            source_url = r.get("url", "")
            img_url = r.get("thumbnail") or r.get("image")
            
            if not img_url:
                continue
                
            try:
                # Fetch image
                resp = session.get(img_url, timeout=5)
                resp.raise_for_status()
                
                content_type = resp.headers.get("Content-Type", "image/jpeg")
                if not content_type.startswith("image/"):
                    content_type = "image/jpeg"
                    
                b64_data = base64.b64encode(resp.content).decode("utf-8")
                
                # Add text info
                content_blocks.append(types.TextContent(
                    type="text", 
                    text=f"\nImage {i}: {title}\nSource: {source_url}"
                ))
                # Add image
                content_blocks.append(types.ImageContent(
                    type="image",
                    data=b64_data,
                    mimeType=content_type
                ))
            except Exception as e:
                content_blocks.append(types.TextContent(
                    type="text", 
                    text=f"\nFailed to load Image {i} ({img_url}): {str(e)}"
                ))
                
        return content_blocks
    except Exception as e:
        logger.error(f"Error searching images: {e}")
        return [types.TextContent(type="text", text=f"Error occurred: {str(e)}")]


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting WebBrowserMCP Server...")
    mcp.run()
