"""pwndbg-mcp: An MCP server exposing pwndbg/GDB to AI agents.

Driven over a PTY against the gdb CLI so the agent receives pwndbg's full
rich output (telescope, context, vmmap, ...) instead of stripped GDB/MI.
"""

__version__ = "0.1.0"
