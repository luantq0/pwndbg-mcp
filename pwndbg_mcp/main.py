"""CLI entry point for pwndbg-mcp."""

from __future__ import annotations

import argparse

from . import tools


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="pwndbg-mcp",
        description="MCP server exposing pwndbg/GDB debugging to AI agents",
    )
    ap.add_argument("--transport", "-t",
                    choices=["stdio", "http", "sse"], default="stdio")
    ap.add_argument("--host", "-H", default="127.0.0.1")
    ap.add_argument("--port", "-p", type=int, default=8780)
    ap.add_argument("--gdb", default="gdb", help="gdb binary (e.g. gdb-multiarch)")
    ap.add_argument("--mcp-path", default="/mcp")
    args = ap.parse_args()

    tools._gdb_bin = args.gdb
    mcp = tools.mcp

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="sse")
    else:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        try:
            mcp.run(transport="streamable-http")
        except Exception:
            mcp.run(transport="http")


if __name__ == "__main__":
    main()
