# LM Studio Web Browser & JS MCP Server

This project is a high-performance and comprehensive **Model Context Protocol (MCP)** server that enables local models running on LM Studio to perform internet searches, read web content, monitor news, execute JavaScript code, and translate text.

## Recent Updates (Performance and Reliability)

- **Parallel Processing:** Using `ThreadPoolExecutor`, reading multiple pages simultaneously has increased speed by 3-5x.
- **Date Injection:** The system date is dynamically embedded into tool descriptions so the model automatically knows today's date.
- **ddgs Library:** Migrated to the latest search engine package (`ddgs`) to avoid rate-limit and 403 errors.

## Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `search_web` | Searches the internet via DuckDuckGo and **automatically reads the pages of found results**, returning full content. |
| 2 | `search_news` | Performs a specialized search for news articles. |
| 3 | `read_webpage` | Extracts title, meta information, and main content text from a single webpage intelligently. |
| 4 | `read_multiple_webpages` | Reads **multiple URLs simultaneously (in parallel)** and combines the results. |
| 5 | `search_and_read` | The most comprehensive research tool: searches, then reads top result pages in parallel and presents them as a unified piece to the model. |
| 6 | `execute_javascript` | Executes JavaScript code securely on V8 (5s timeout, 64MB RAM limit). |
| 7 | `get_current_datetime` | Provides current date, time, and day information. |
| 8 | `translate_text` | Translates text to the desired language (default: English). |
| 9 | `search_images` | *(NEW)* Performs image search on the internet and sends found images directly to the model's visual memory. |

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

## LM Studio Integration

To add this MCP server to LM Studio:

1. Open LM Studio.
2. Go to **Program** (or Settings) in the right-side menu.
3. Navigate to **MCP Servers** -> **Edit mcp.json**.
4. Edit `mcp.json` file using absolute paths as shown below:

   ```json
   {
     "mcpServers": {
       "web-and-js-tools": {
         "command": "YOUR_PATH_TO_PYTHON/Scripts/python.exe",
         "args": [
           "YOUR_PATH_TO_PROJECT/mcp_server.py"
         ]
       }
     }
   }
   ```

   *Note: On Windows, use forward slashes (`/`) instead of backslashes (`\`).*

## Recommended System Prompt

Paste the following into LM Studio's **System Prompt** field so the model actively uses the tools without resistance:

```text
You are an advanced AI with direct access to the live internet. You have the ability to run JavaScript, translate text, and show VISUAL/PHOTOS TO THE USER. NEVER say phrases like "I am an AI and cannot access real-time information", "I don't have real-time information access", or "I cannot directly share visual/photos". You CAN use your tools for these tasks.

- When asked about something you don't know or that's current, ZORUNLU (REQUIRED) use the "search_web", "search_news", or "search_and_read" tool.
- When a user wants to see a photo or image, ZORUNLU (REQUIRED) use the "search_images" tool. This will display the photo directly to the user.
- For calculations or algorithmic tasks, run code using "execute_javascript".
- Use "translate_text" for translating text in foreign languages.
```

## Usage Examples

- "Search the internet: What are today's most important technology news?"
- "What was yesterday's Euro/TL exchange rate?"
- "Write and run a JS program that finds prime numbers from 1 to 1000."
- "Translate this article to English: ..."

## License

This project is open source. Feel free to use, modify, and distribute it as needed.