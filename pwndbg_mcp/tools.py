"""FastMCP tool surface for pwndbg-mcp.

Design goals (per project requirements):
  * Extract *all* of pwndbg's output and return it to the agent as text.
  * If text extraction looks empty/broken, fall back to a PNG snapshot the
    agent can read visually (as_image / snapshot tools).
  * Be able to attach() to a live PID, drive the debug session, and support
    the find-the-offset workflow (cyclic, ni, telescope, canary).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP, Image

from .gdb_controller import GdbController
from .snapshot import text_to_png

mcp = FastMCP("pwndbg")

_ctrl: GdbController | None = None
_gdb_bin = "gdb"


def ctrl() -> GdbController:
    global _ctrl
    if _ctrl is None or not _ctrl.is_alive():
        _ctrl = GdbController(_gdb_bin)
    return _ctrl


def _result(text: str, title: str = "", as_image: bool = False):
    """Return cleaned text, or a PNG snapshot when explicitly requested.

    A command that legitimately produces no output (e.g. `set ...`) returns a
    short text marker, not an image of raw escape codes. Image rendering always
    uses the *cleaned* text so the snapshot is human-readable.
    """
    text = text or ""
    if not as_image:
        return text if text.strip() else "(no output)"
    try:
        png = text_to_png(text if text.strip() else "(no output)", title)
        return Image(data=png, format="png")
    except Exception as e:  # never let snapshot kill the tool
        return text or f"(empty; snapshot failed: {e})"


# --------------------------------------------------------------- session mgmt
@mcp.tool()
def pwndbg_status() -> str:
    """Report whether a gdb/pwndbg session is alive."""
    global _ctrl
    if _ctrl is None:
        return "no session (will be created on first command)"
    return f"alive={_ctrl.is_alive()} gdb={_gdb_bin}"


@mcp.tool()
def pwndbg_hard_reset() -> str:
    """Kill and restart the gdb/pwndbg session from scratch."""
    return ctrl().hard_reset() or "reset ok"


@mcp.tool()
def load_executable(path: str, args: str = "") -> str:
    """Load an ELF into gdb (`file <path>`), optionally set run args."""
    out = ctrl().cmd(f"file {path}")
    if args:
        out += "\n" + ctrl().cmd(f"set args {args}")
    out += "\n" + ctrl().cmd("checksec")
    return out


# --------------------------------------------------------------- execution
@mcp.tool()
def debug_run(stdin_input: str = "", as_image: bool = False):
    """Run the inferior (`run`). Returns output once it stops or goes idle."""
    out = ctrl().run_inferior("run")
    if stdin_input:
        out += "\n" + ctrl().send_process(stdin_input.encode())
    return _result(out, "run", as_image)


@mcp.tool()
def debug_continue(as_image: bool = False):
    """Continue execution (`continue`)."""
    return _result(ctrl().run_inferior("continue"), "continue", as_image)


@mcp.tool()
def debug_stepi(count: int = 1, as_image: bool = False):
    """Step one machine instruction (`stepi`)."""
    return _result(ctrl().resume(f"stepi {count}", idle=0.4), "stepi", as_image)


@mcp.tool()
def debug_nexti(count: int = 1, as_image: bool = False):
    """Step over one machine instruction (`nexti`)."""
    return _result(ctrl().resume(f"nexti {count}", idle=0.4), "nexti", as_image)


@mcp.tool()
def debug_next(count: int = 1, as_image: bool = False):
    """Source-level next (`next`)."""
    return _result(ctrl().resume(f"next {count}", idle=0.5), "next", as_image)


@mcp.tool()
def debug_step(count: int = 1, as_image: bool = False):
    """Source-level step (`step`)."""
    return _result(ctrl().resume(f"step {count}", idle=0.5), "step", as_image)


@mcp.tool()
def debug_finish(as_image: bool = False):
    """Run until the current function returns (`finish`)."""
    return _result(ctrl().run_inferior("finish"), "finish", as_image)


@mcp.tool()
def debug_until(location: str = "", as_image: bool = False):
    """Run until a location is reached (`until [location]`)."""
    return _result(ctrl().resume(f"until {location}".strip(), idle=0.6),
                   "until", as_image)


@mcp.tool()
def debug_jump(location: str, as_image: bool = False):
    """Jump to an address/label and continue (`jump <location>`)."""
    return _result(ctrl().resume(f"jump {location}", idle=0.6), "jump", as_image)


@mcp.tool()
def debug_kill() -> str:
    """Kill the inferior process."""
    return ctrl().cmd("kill") or "killed"


# --------------------------------------------------------------- breakpoints
@mcp.tool()
def breakpoint_set(location: str, temporary: bool = False,
                   condition: str = "") -> str:
    """Set a breakpoint. `location` e.g. 'main', '*challenge+254', '*0x1803'."""
    kw = "tbreak" if temporary else "break"
    cmd = f"{kw} {location}"
    if condition:
        cmd += f" if {condition}"
    return ctrl().cmd(cmd)


@mcp.tool()
def breakpoint_list() -> str:
    """List breakpoints (`info breakpoints`)."""
    return ctrl().cmd("info breakpoints")


@mcp.tool()
def breakpoint_delete(num: str = "") -> str:
    """Delete a breakpoint by number, or all if empty."""
    return ctrl().cmd(f"delete {num}".strip())


# --------------------------------------------------------------- inspection
@mcp.tool()
def inspect_registers(regs: str = "", as_image: bool = False):
    """Show registers (pwndbg `regs`). Optionally restrict to e.g. 'rip rsp'."""
    return _result(ctrl().cmd(f"regs {regs}".strip()), "regs", as_image)


@mcp.tool()
def inspect_memory(addr: str, count: int = 8, fmt: str = "gx",
                   as_image: bool = False):
    """Examine memory: `x/<count><fmt> <addr>` (default 8 qwords hex)."""
    return _result(ctrl().cmd(f"x/{count}{fmt} {addr}"), f"x {addr}", as_image)


@mcp.tool()
def inspect_expression(expr: str) -> str:
    """Evaluate a gdb expression (`print`)."""
    return ctrl().cmd(f"print {expr}")


@mcp.tool()
def telescope(addr: str = "$rsp", count: int = 20, as_image: bool = False):
    """pwndbg `telescope`: dereference a pointer chain from addr."""
    return _result(ctrl().cmd(f"telescope {addr} {count}"),
                   f"telescope {addr}", as_image)


@mcp.tool()
def context(as_image: bool = False):
    """pwndbg `context`: regs + code + stack + backtrace (text; as_image opt-in)."""
    return _result(ctrl().cmd("context"), "context", as_image)


@mcp.tool()
def backtrace(as_image: bool = False):
    """Call stack (`backtrace`)."""
    return _result(ctrl().cmd("backtrace"), "backtrace", as_image)


@mcp.tool()
def vmmap(query: str = "", as_image: bool = False):
    """Virtual memory map (pwndbg `vmmap`)."""
    return _result(ctrl().cmd(f"vmmap {query}".strip()), "vmmap", as_image)


@mcp.tool()
def canary(as_image: bool = False):
    """Show the stack canary value (pwndbg `canary`)."""
    return _result(ctrl().cmd("canary"), "canary", as_image)


@mcp.tool()
def checksec() -> str:
    """Security mitigations of the loaded binary (pwndbg `checksec`)."""
    return ctrl().cmd("checksec")


@mcp.tool()
def disassemble(where: str = "", count: int = 0, as_image: bool = False):
    """Disassemble. `where` like 'challenge' or '$pc'; count limits lines."""
    # prefer pwndbg's nearpc for $pc context
    if not where or where in ("$pc", "pc"):
        out = ctrl().cmd(f"nearpc {count or 15}")
    else:
        out = ctrl().cmd(f"disassemble {where}")
    return _result(out, "disasm", as_image)


@mcp.tool()
def search_memory(value: str, kind: str = "auto") -> str:
    """Search mapped memory for a value/string (pwndbg `search`).

    kind: 'auto' | 'string' | 'qword' | 'dword' | 'bytes'.
    """
    flag = {"string": "-t string", "qword": "-8", "dword": "-4",
            "bytes": "-x", "auto": ""}.get(kind, "")
    return ctrl().cmd(f"search {flag} {value}".strip())


@mcp.tool()
def got_plt(as_image: bool = False):
    """Show GOT entries (pwndbg `got`)."""
    return _result(ctrl().cmd("got"), "got", as_image)


# --------------------------------------------------------------- offsets (cyclic)
@mcp.tool()
def cyclic_gen(length: int = 200) -> str:
    """Generate a De Bruijn cyclic pattern of `length` bytes (pwndbg `cyclic`)."""
    return ctrl().cmd(f"cyclic {length}")


@mcp.tool()
def cyclic_find(value: str) -> str:
    """Find the offset of a 4/8-byte value inside the cyclic pattern.

    Pass a hex value (e.g. the faulting $rsp top) — solves RIP/RBP/canary
    offset discovery after a crash.
    """
    return ctrl().cmd(f"cyclic -l {value}")


# --------------------------------------------------------------- process I/O
@mcp.tool()
def send_to_process(text: str, newline: bool = True,
                    read_after: float = 0.4) -> str:
    """Send a line to the inferior's stdin and read what comes back."""
    data = text.encode() + (b"\n" if newline else b"")
    return ctrl().send_process(data, read_after=read_after)


@mcp.tool()
def send_bytes_to_process(hex_bytes: str, read_after: float = 0.4) -> str:
    """Send raw bytes (hex string) to the inferior's stdin."""
    data = bytes.fromhex(hex_bytes.replace(" ", "").replace("\n", ""))
    return ctrl().send_process(data, read_after=read_after)


@mcp.tool()
def read_from_process(read_after: float = 0.5) -> str:
    """Read buffered output from the inferior."""
    return ctrl().read_process(read_after=read_after)


@mcp.tool()
def interrupt_process() -> str:
    """Send Ctrl-C to the inferior."""
    return ctrl().interrupt()


# --------------------------------------------------------------- attach / raw
@mcp.tool()
def attach(pid: int, as_image: bool = False):
    """Attach to a running PID (e.g. one printed by a pwntools exploit that
    paused on input()). Returns the stop context."""
    out = ctrl().cmd(f"attach {pid}", timeout=30, idle=1.0)
    return _result(out, f"attach {pid}", as_image)


@mcp.tool()
def detach() -> str:
    """Detach from the current inferior (`detach`)."""
    return ctrl().cmd("detach")


@mcp.tool()
def execute_command(command: str, idle: float = 0.0, as_image: bool = False):
    """Run any raw gdb/pwndbg command and return its full output.

    Set idle>0 for commands that resume the inferior (run/continue/until).
    Set as_image=True to receive a PNG snapshot of the output.
    """
    out = ctrl().cmd(command, idle=(idle or None))
    return _result(out, command, as_image)


@mcp.tool()
def snapshot(command: str = "context") -> Image:
    """Always return a PNG image of `command`'s output (visual fallback)."""
    out = ctrl().cmd(command, idle=0.4)
    png = text_to_png(out or _ctrl.last_raw.decode("utf-8", "replace"), command)
    return Image(data=png, format="png")


@mcp.tool()
def info_address(symbol: str) -> str:
    """Resolve a symbol's address (`info address`)."""
    return ctrl().cmd(f"info address {symbol}")


@mcp.tool()
def info_symbol(addr: str) -> str:
    """Resolve the symbol at an address (`info symbol`)."""
    return ctrl().cmd(f"info symbol {addr}")


# --------------------------------------------------------------- mutate state
@mcp.tool()
def set_register(reg: str, value: str) -> str:
    """Set a register, e.g. set_register('rdi', '0x1337')."""
    return ctrl().cmd(f"set ${reg} = {value}") or f"${reg} = {value}"


@mcp.tool()
def write_memory(addr: str, value: str, size: str = "qword") -> str:
    """Write a value to memory. size: byte|word|dword|qword."""
    t = {"byte": "char", "word": "short", "dword": "int",
         "qword": "long long"}.get(size, "long long")
    return ctrl().cmd(f"set {{{t}}}({addr}) = {value}") or "ok"


@mcp.tool()
def watchpoint_set(expr: str, kind: str = "write") -> str:
    """Set a watchpoint. kind: write|read|access."""
    cmd = {"write": "watch", "read": "rwatch", "access": "awatch"}.get(kind, "watch")
    return ctrl().cmd(f"{cmd} {expr}")
