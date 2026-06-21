# pwndbg-mcp

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/Protocol-MCP-purple)](https://modelcontextprotocol.io)

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes GDB + pwndbg debugging capabilities to AI agents such as Claude Code and Claude Desktop. Designed for CTF binary exploitation and general reverse-engineering workflows.

---

## Features

- **PTY-driven CLI** — Controls GDB through a pseudo-terminal so the agent receives pwndbg's full rich output (`telescope`, `context`, `vmmap`, ...) rather than the stripped output of GDB/MI. Command completion is synchronized with an echoed sentinel, not a fragile prompt match.
- **Visual fallback (PNG)** — Any tool accepts `as_image=true` to return a rendered PNG image that the agent reads visually, useful when plain-text layout is hard to parse.
- **Attach to live processes** — `attach(pid)` connects to a running process (e.g. a pwntools exploit paused at `input()`), lets you inspect and modify state, then allows the exploit to continue.
- **Token-efficient** — Only exposes GDB/pwndbg primitives; file I/O and shell commands are delegated to the agent's own tools (Read/Write/Bash). pwndbg output is compacted before being returned to reduce token usage.
- **Offset discovery** — `cyclic_gen` / `cyclic_find` for RIP/RBP/canary offset finding after a crash.
- **pwndbg shortcuts** — `telescope`, `context`, `vmmap`, `canary`, `checksec`, `got`, `search`, `regs`, `nearpc`, and more.
- **Process I/O** — Send lines, raw bytes, and Ctrl-C to the inferior via the PTY.
- **Three transports** — `stdio` (default, for Claude Code/Desktop), `http` (streamable), and `sse`.
- **Multi-arch** — Supports `gdb-multiarch` via the `--gdb` flag.
- **MIT License** — Free to use, fork, and distribute.

---

## Requirements

- Python 3.10 or later
- GDB with pwndbg installed (pwndbg auto-loads via `~/.gdbinit`)
- `mcp` (FastMCP) and `pillow` — installed automatically as dependencies

`pygdbmi` is not required.

---

## Installation

### Using uv (recommended)

```bash
git clone https://github.com/luantq0/pwndbg-mcp.git
cd pwndbg-mcp

# Install as a global tool
uv tool install .

# Or run directly from the clone directory
uv run pwndbg-mcp
```

### Using pip

```bash
git clone https://github.com/luantq0/pwndbg-mcp.git
cd pwndbg-mcp
pip install .
pwndbg-mcp
```

On Kali/Debian systems that restrict pip outside virtual environments:

```bash
pip install . --break-system-packages
```

---

## Quick Start

```
usage: pwndbg-mcp [-h] [--transport {stdio,http,sse}] [--host HOST] [--port PORT]
                  [--gdb BINARY] [--mcp-path MCP_PATH]

options:
  -h, --help                        Show this help message and exit
  --transport, -t {stdio,http,sse}  Transport mode (default: stdio)
  --host, -H HOST                   Host for HTTP/SSE modes (default: 127.0.0.1)
  --port, -p PORT                   Port for HTTP/SSE modes (default: 8780)
  --gdb BINARY                      GDB binary to use (default: gdb)
  --mcp-path MCP_PATH               URL path for the HTTP endpoint (default: /mcp)
```

```bash
# stdio — for Claude Code / Claude Desktop
pwndbg-mcp --transport stdio

# HTTP (streamable) — for most MCP clients
pwndbg-mcp --transport http

# SSE — for older MCP clients
pwndbg-mcp --transport sse --port 8780

# Multi-arch (ARM, MIPS, ...)
pwndbg-mcp --gdb gdb-multiarch
```

---

## Configuration

### Claude Code (stdio, recommended)

```bash
claude mcp add pwndbg -- pwndbg-mcp --transport stdio
```

**Running GDB inside WSL from Windows:**

```bash
claude mcp add pwndbg -- wsl -d kali-linux -- \
  bash -c 'cd /path/to/pwndbg-mcp && exec python3 -m pwndbg_mcp.main --transport stdio'
```

### Claude Desktop (stdio)

Add to `~/.config/claude/claude_desktop_config.json` (Linux/macOS) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "pwndbg": {
      "command": "pwndbg-mcp",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### HTTP Streamable

Start the server:

```bash
pwndbg-mcp --transport http --port 8780
```

Configure the client:

```json
{
  "mcpServers": {
    "pwndbg": {
      "transport": {
        "type": "http",
        "url": "http://127.0.0.1:8780/mcp"
      }
    }
  }
}
```

---

## Attach Workflow

The primary CTF workflow: run your exploit, pause it, attach from pwndbg-mcp, inspect and modify state, then let the exploit continue.

**Exploit template:**

```python
import ctypes
from pwn import *

# Allow external GDB attach even when ptrace_scope=1
ctypes.CDLL("libc.so.6").prctl(0x59616d61, -1, 0, 0, 0)  # PR_SET_PTRACER_ANY

p = process("./challenge")
print("PID =", p.pid, flush=True)
input()              # pause here so the agent can attach
# ... send payload ...
p.interactive()
```

**Steps:**

1. Agent runs the exploit in the background via Bash, captures `PID=...`
2. Agent calls `attach(pid)` — inspects context, sets breakpoints, checks canary, telescopes the stack
3. Agent writes `\n` to the exploit's stdin (via Bash) to release `input()` and let the payload send
4. Agent edits the exploit and repeats until `/flag` is read

> On systems where you have root access, `echo 0 > /proc/sys/kernel/yama/ptrace_scope` removes the need for `PR_SET_PTRACER_ANY`.

---

## MCP Tool Reference

### Session Management

| Tool | Description |
|------|-------------|
| `load_executable` | Load an ELF binary into GDB (`file <path>`), optionally set run args |
| `pwndbg_status` | Report whether a GDB session is currently active |
| `pwndbg_hard_reset` | Kill and restart the GDB session from scratch |

### Execution Control

| Tool | Description |
|------|-------------|
| `debug_run` | Run the inferior (`run`) |
| `debug_continue` | Continue execution (`continue`) |
| `debug_step` | Source-level step into a function (`step`) |
| `debug_next` | Source-level step over a function (`next`) |
| `debug_stepi` | Step one machine instruction (`stepi`) |
| `debug_nexti` | Step over one machine instruction (`nexti`) |
| `debug_finish` | Run until the current function returns (`finish`) |
| `debug_until` | Run until a given location (`until`) |
| `debug_jump` | Jump to an address or label and continue (`jump`) |
| `debug_kill` | Kill the inferior process |

### Breakpoints and Watchpoints

| Tool | Description |
|------|-------------|
| `breakpoint_set` | Set a breakpoint (supports temporary and conditional variants) |
| `breakpoint_list` | List all breakpoints (`info breakpoints`) |
| `breakpoint_delete` | Delete a breakpoint by number, or all breakpoints |
| `watchpoint_set` | Set a watchpoint (`watch` / `rwatch` / `awatch`) |

### Memory and Register Inspection

| Tool | Description |
|------|-------------|
| `inspect_registers` | Show registers (pwndbg `regs`) |
| `inspect_memory` | Examine memory (`x/<count><fmt> <addr>`) |
| `inspect_expression` | Evaluate a GDB expression (`print`) |
| `disassemble` | Disassemble a function or address (uses pwndbg `nearpc` at `$pc`) |
| `set_register` | Set a register to a value |
| `write_memory` | Write a byte/word/dword/qword to a memory address |

### pwndbg Shortcuts

| Tool | Description |
|------|-------------|
| `context` | Full pwndbg context (registers, code, stack, backtrace) |
| `telescope` | Dereference a pointer chain from an address |
| `vmmap` | Virtual memory map of the process |
| `backtrace` | Current call stack |
| `canary` | Show the stack canary value |
| `checksec` | Binary security mitigations |
| `got_plt` | GOT/PLT entries |
| `search_memory` | Search mapped memory for a value, string, or byte sequence |

### Process I/O

| Tool | Description |
|------|-------------|
| `send_to_process` | Send a line to the inferior's stdin and read the response |
| `send_bytes_to_process` | Send raw bytes (hex string) to the inferior's stdin |
| `read_from_process` | Read buffered output from the inferior |
| `interrupt_process` | Send Ctrl-C to the inferior |

### Offset Discovery (cyclic)

| Tool | Description |
|------|-------------|
| `cyclic_gen` | Generate a De Bruijn pattern of N bytes (`cyclic <N>`) |
| `cyclic_find` | Find the offset of a faulting value (e.g. `$rsp`) in the pattern |

### Symbol Information

| Tool | Description |
|------|-------------|
| `info_symbol` | Resolve the symbol name at an address |
| `info_address` | Resolve the address of a symbol name |

### Attach and Visual Output

| Tool | Description |
|------|-------------|
| `attach` | Attach to a running PID |
| `detach` | Detach from the inferior |
| `snapshot` | Return a PNG image of a command's output (always visual) |
| `execute_command` | Run any raw GDB/pwndbg command and return its output |

### Notes on Token Usage

pwndbg output is compacted before being returned:
- Long separator lines (`─`, `═`) are collapsed to `──`
- The `LEGEND` banner is dropped
- Consecutive blank lines are squeezed to one blank line

This reduces quota usage by roughly 80% for `context` and `telescope` output. PNG images (`as_image=true` or `snapshot`) are always opt-in since they cost more tokens than equivalent text.

---

## Security

> **Warning:** The `execute_command`, `load_executable`, and `send_bytes_to_process` tools can execute arbitrary code on your machine.

- Never expose this server on a public network interface.
- Always use `--host 127.0.0.1` (the default) to bind to localhost only.
- For additional isolation, run inside `bwrap`:

```bash
bwrap --ro-bind / / \
      --overlay-src ~ --tmp-overlay ~ \
      --dev-bind /dev /dev \
      --proc /proc \
      --tmpfs /tmp \
      --unshare-pid \
      bash -c "pwndbg-mcp --transport stdio"
```
> Notice: If you discover any vulnerabilities, please report them to me via the Security and quality tab.
---

## Architecture

```
pwndbg_mcp/
├── __init__.py          # Package version
├── gdb_controller.py    # PTY-based GDB/pwndbg controller
├── snapshot.py          # Text-to-PNG renderer (Pillow) for visual fallback
├── tools.py             # MCP tool definitions (FastMCP)
└── main.py              # CLI entry point and server startup

tests/
└── test_gdb_controller.py  # Unit tests (no GDB required) + integration test
```

**Data flow:**

```
AI Agent (Claude)
    |  MCP (stdio / HTTP / SSE)
    v
FastMCP Server  -->  tools.py  -->  GdbController
                         |               |
                   snapshot.py       PTY (master fd)
                   (PNG fallback)        |
                                   gdb + pwndbg (CLI)
                                          |
                                   Inferior process
```

Because control goes through the real GDB CLI rather than GDB/MI, the agent receives exactly what pwndbg displays — including `telescope`, `context`, and color-coded register output. Commands are synchronized with an echoed sentinel; resuming commands (`run`, `continue`, `stepi`, ...) use an idle-based drain so they do not consume the inferior's stdin.

---

## Development

```bash
git clone https://github.com/luantq0/pwndbg-mcp.git
cd pwndbg-mcp

# Install with dev dependencies
uv sync --all-extras

# Run tests (unit tests do not require GDB)
uv run pytest tests/ -v

# Format and lint
uv run black pwndbg_mcp/ tests/
uv run ruff check pwndbg_mcp/ tests/
```

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Fork** the repository and create a feature branch from `main`.
2. **Write tests** for new behavior. Pure-logic tests that do not require a live GDB session are preferred, but integration tests are also welcome.
3. **Run the test suite** and linters before submitting:
   ```bash
   uv run pytest tests/ -v
   uv run black pwndbg_mcp/ tests/
   uv run ruff check pwndbg_mcp/ tests/
   ```
4. **Submit a pull request** with a clear description of the change and the motivation behind it.
5. **One logical change per PR** — keep pull requests focused.

For bugs or feature requests, open a GitHub issue with a minimal reproducible example where applicable.

---

## License

MIT License — Copyright (c) 2026 Luan Tran

See [LICENSE](LICENSE) for the full text.

---

## Related Projects

- [pwndbg](https://github.com/pwndbg/pwndbg) — The GDB plugin this server interfaces with
- [Model Context Protocol](https://modelcontextprotocol.io) — MCP specification
- [FastMCP](https://github.com/PrefectHQ/fastmcp) — MCP server framework (Apache 2.0)
- [pwntools](https://github.com/Gallopsled/pwntools) — CTF exploit framework
