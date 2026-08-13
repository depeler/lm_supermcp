from mcp.server.fastmcp import FastMCP
mcp = FastMCP('test')
@mcp.tool(description='dynamic')
def foo(): pass
import asyncio
print(asyncio.run(mcp.list_tools())[0].description)
