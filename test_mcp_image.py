from mcp.server.fastmcp import FastMCP, Image
import mcp.types as types
mcp = FastMCP('test')
@mcp.tool()
def foo(): return [types.TextContent(type='text', text='hi'), types.ImageContent(type='image', data='cmF3', mimeType='image/png')]
import asyncio
async def run():
  res = await mcp._tool_manager.call_tool('foo', {})
  print(res)
asyncio.run(run())
