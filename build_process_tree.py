#!/usr/bin/env python3
"""Build a text process tree from a Windows event-log JSON export."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from collections import defaultdict


# ---------------- robust loading ----------------

def load_events(path):
    try:
        if path:
            with open(path, "r", encoding="utf-8-sig") as f:
                raw = f.read()
        else:
            raw = sys.stdin.read()
    except FileNotFoundError:
        sys.exit(f"[fatal] file not found: {path}")
    except OSError as e:
        sys.exit(f"[fatal] cannot read {path}: {e}")

    print(f"[info] read {len(raw):,} chars", file=sys.stderr, flush=True)
    if not raw.strip():
        sys.exit("[fatal] input is empty")

    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1:
        sys.exit("[fatal] no JSON object found in input")
    if start > 0 or end < len(raw) - 1:
        print(f"[info] stripped {start} leading / {len(raw) - end - 1} trailing chars",
              file=sys.stderr, flush=True)
    text = raw[start:end + 1]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        sys.exit(
            f"[fatal] invalid JSON at line {e.lineno}, column {e.colno}: {e.msg}\n"
            f"        Context near error: {text[max(0, e.pos - 40):e.pos + 40]!r}\n"
            "        The file is probably truncated — check it ends with\n"
            "        a complete event object, then '  ]' and '}'."
        )

    if not isinstance(data, dict):
        sys.exit(f"[fatal] top-level JSON should be an object, got {type(data).__name__}")
    if "events" not in data:
        sys.exit(f"[fatal] no 'events' key. Top-level keys: {list(data)}")
    events = data["events"]
    if not isinstance(events, list):
        sys.exit(f"[fatal] 'events' should be a list, got {type(events).__name__}")
    if not events:
        sys.exit("[fatal] 'events' is empty")
    print(f"[info] {len(events)} event(s) loaded", file=sys.stderr, flush=True)
    return events


# ---------------- PowerShell -EncodedCommand decoding ----------------

_ENCODED_RE = re.compile(
    r'-(?:enc(?:odedcommand)?)\s+([A-Za-z0-9+/]{4,}={0,2})'
    r'|'
    r'-e\s+([A-Za-z0-9+/]{20,}={0,2})',
    re.IGNORECASE,
)


def _try_decode_ps(b64):
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        raw = base64.b64decode(padded, validate=True)
    except Exception:
        return None
    if raw.startswith(b"\xff\xfe"):
        raw = raw[2:]
    for enc in ("utf-16-le", "utf-8"):
        try:
            s = raw.decode(enc)
        except Exception:
            continue
        if not s:
            continue
        good = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
        if good / len(s) >= 0.9:
            return s
    return None


def _find_encoded_blobs(cmdline):
    results = []
    for m in _ENCODED_RE.finditer(cmdline):
        if m.group(1) is not None:
            b64, start, end = m.group(1), m.start(1), m.end(1)
        else:
            b64, start, end = m.group(2), m.start(2), m.end(2)
        dec = _try_decode_ps(b64)
        if dec is not None:
            results.append((start, end, b64, dec))
    return results


def _nlines(dec):
    return dec.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n").count("\n") + 1


# ---------------- timestamp formatting ----------------

_TIME_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$'
)


def _fmt_time(ts):
    if not ts:
        return ""
    m = _TIME_RE.match(ts)
    if not m:
        return ts
    date, hms, frac, tz = m.groups()
    out = f"{date} {hms}"
    if frac:
        out += "." + frac[:3].ljust(3, "0")
    if tz == "Z":
        out += " UTC"
    elif tz:
        if ":" not in tz:
            tz = tz[:3] + ":" + tz[3:]
        out += f" {tz}"
    return out


# ---------------- color palette ----------------

class Palette:
    def __init__(self, enabled):
        self.enabled = bool(enabled)

    def _wrap(self, code, s):
        if not self.enabled or not s:
            return s
        return f"\x1b[{code}m{s}\x1b[0m"

    def bold(self, s):     return self._wrap("1", s)
    def dim(self, s):      return self._wrap("2", s)
    def cyan(self, s):     return self._wrap("96", s)
    def green(self, s):    return self._wrap("92", s)
    def magenta(self, s):  return self._wrap("95", s)


# ---------------- tree construction ----------------

def _user(text):
    marker = "The user "
    if text and marker in text:
        return text.split(marker, 1)[1].split(" ", 1)[0]
    return None


def parse_events(events):
    procs = {}
    for ev in events:
        pid = ev.get("object.process.id")
        if pid is None:
            continue
        pid = str(pid)
        ppid = ev.get("object.process.parent.id")
        ppid = str(ppid) if ppid else None
        cmdline = ev.get("object.process.cmdline")
        etype = ev.get("id") or ""
        text = ev.get("text") or ""
        ts = ev.get("time") or ""
        host = ev.get("event_src.host")
        is_creation = "Process_creation" in etype or "A_new_process" in etype
        user = _user(text)

        p = procs.setdefault(pid, {
            "cmdline": "", "ppid": None, "time": "", "user": None,
            "host": None,
            "is_creation": False, "detections": [],
        })
        if cmdline and not p["cmdline"]:
            p["cmdline"] = cmdline
        if ppid and not p["ppid"]:
            p["ppid"] = ppid
        if user and not p["user"]:
            p["user"] = user
        if ts and not p["time"]:
            p["time"] = ts
        if host and not p["host"]:
            p["host"] = host
        if is_creation:
            p["is_creation"] = True
        if not is_creation and not cmdline and text:
            p["detections"].append(text)

    children = defaultdict(list)
    roots = []
    for pid, p in procs.items():
        if p["ppid"] and p["ppid"] in procs:
            children[p["ppid"]].append(pid)
        else:
            roots.append(pid)

    key = lambda x: procs[x]["time"]
    for c in children.values():
        c.sort(key=key)
    roots.sort(key=key)
    return procs, children, roots


# ---------------- subtree / tree filtering ----------------

def find_root_ancestor(pid, procs):
    seen = set()
    cur = pid
    while True:
        if cur in seen:
            return cur
        seen.add(cur)
        ppid = procs.get(cur, {}).get("ppid")
        if not ppid or ppid not in procs:
            return cur
        cur = ppid


def find_ancestors(pid, procs):
    out, seen, cur = [], {pid}, pid
    while True:
        ppid = procs.get(cur, {}).get("ppid")
        if not ppid or ppid not in procs or ppid in seen:
            return out
        seen.add(ppid)
        out.append(ppid)
        cur = ppid


def collect_subtree(root, children):
    result = set()
    stack = [root]
    while stack:
        p = stack.pop()
        if p in result:
            continue
        result.add(p)
        stack.extend(children.get(p, []))
    return result


def filter_tree(procs, children, roots, mode, target_pid):
    target = str(target_pid)
    if target not in procs:
        lines = [f"[fatal] PID {target} not found in events."]
        refs = [p for p, v in procs.items() if v["ppid"] == target]
        if refs:
            lines.append(
                f"        It only appears as a parent reference of PID(s): "
                f"{', '.join(refs[:10])}" + (" ..." if len(refs) > 10 else "")
            )
        if roots:
            lines.append("        Available root PIDs:")
            for r in roots[:10]:
                preview = (procs[r]["cmdline"] or "(no cmdline)")[:60]
                lines.append(f"          {r:>6}  {preview}")
            if len(roots) > 10:
                lines.append(f"          ... ({len(roots) - 10} more)")
        sys.exit("\n".join(lines))

    if mode == "pid":
        new_root = target
        ancestors = find_ancestors(target, procs)
    else:
        new_root = find_root_ancestor(target, procs)
        ancestors = []

    keep = collect_subtree(new_root, children)
    new_procs = {p: procs[p] for p in keep}
    new_children = defaultdict(list)
    for p in keep:
        new_children[p] = [c for c in children.get(p, []) if c in keep]
    return new_procs, new_children, [new_root], ancestors


# ---------------- helpers for host summary ----------------

def _hosts_in(procs_dict):
    return sorted({v["host"] for v in procs_dict.values() if v.get("host")})


def _host_line(procs_dict):
    hosts = _hosts_in(procs_dict)
    if not hosts:
        return ""
    if len(hosts) == 1:
        return f" \u2014 host: {hosts[0]}"
    return f" \u2014 hosts: {', '.join(hosts)}"


# ---------------- rendering ----------------

def _prepare_cmdline(cmdline, decode):
    if not decode or not cmdline:
        return cmdline, []
    blobs = _find_encoded_blobs(cmdline)
    if not blobs:
        return cmdline, []
    parts, decoded, last = [], [], 0
    for start, end, b64, dec in blobs:
        parts.append(cmdline[last:start])
        parts.append(f"<decoded: {_nlines(dec)} line(s)>")
        decoded.append((b64, dec))
        last = end
    parts.append(cmdline[last:])
    return "".join(parts), decoded


def render(procs, children, roots, max_cmd=None, decode=False, palette=None,
           show_host=False):
    if palette is None:
        palette = Palette(False)
    out, seen = [], set()

    def short(c):
        if max_cmd is None or len(c) <= max_cmd:
            return c
        return c[: max_cmd - 3] + "..."

    def walk(pid, prefix, is_last, is_root):
        if pid in seen:
            conn = "" if is_root else (palette.dim("\u2514\u2500\u2500 ") if is_last
                                        else palette.dim("\u251c\u2500\u2500 "))
            out.append(
                f"{prefix}{conn}{palette.magenta(f'[PID {pid}]')} "
                f"{palette.dim('(see above)')}\n"
            )
            return
        seen.add(pid)

        p = procs[pid]
        display_cmd, decoded_blocks = _prepare_cmdline(p["cmdline"], decode)

        if display_cmd:
            cmd_str = short(display_cmd)
            if decode and "<decoded:" in cmd_str:
                pieces = re.split(r'(<decoded: [^>]+>)', cmd_str)
                cmd_str = "".join(
                    palette.cyan(piece) if piece.startswith("<decoded:")
                    else palette.green(piece)
                    for piece in pieces if piece
                )
            else:
                cmd_str = palette.green(cmd_str)
        else:
            cmd_str = palette.dim("(no cmdline captured)")

        meta_parts = []
        if show_host and p.get("host"):
            meta_parts.append(palette.dim(f"host={p['host']}"))
        if p["user"]:
            meta_parts.append(palette.cyan(f"user={p['user']}"))
        if p["time"]:
            meta_parts.append(palette.dim(_fmt_time(p["time"])))
        if meta_parts:
            sep = palette.dim(" | ")
            meta_str = f"  {palette.dim('[')}{sep.join(meta_parts)}{palette.dim(']')}"
        else:
            meta_str = ""

        conn = "" if is_root else (palette.dim("\u2514\u2500\u2500 ") if is_last
                                    else palette.dim("\u251c\u2500\u2500 "))
        out.append(
            f"{prefix}{conn}{palette.magenta(f'[PID {pid}]')} {cmd_str}{meta_str}\n"
        )

        cprefix = prefix + (
            "" if is_root
            else (palette.dim("    ") if is_last else palette.dim("\u2502   "))
        )

        for det in p["detections"]:
            out.append(f"{cprefix}    {palette.bold('!')} {palette.bold(det)}\n")

        for b64, dec in decoded_blocks:
            lines = dec.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n").split("\n")
            out.append(
                f"{cprefix}    {palette.cyan('~')} decoded "
                f"{palette.dim(f'({len(b64)} b64 chars -> {len(lines)} line(s))')}:\n"
            )
            for line in lines:
                out.append(f"{cprefix}      {palette.dim(line)}\n")

        kids = children.get(pid, [])
        for i, c in enumerate(kids):
            walk(c, cprefix, i == len(kids) - 1, False)

    for r in roots:
        walk(r, "", True, True)
    return "".join(out)


# ---------------- CLI ----------------

def build_argparser():
    ap = argparse.ArgumentParser(
        description="Build a text process tree from a Windows event-log JSON export.",
    )
    ap.add_argument("file", nargs="?", default=None,
                    help="JSON export (omit or '-' to read from stdin)")
    ap.add_argument("--full", "-f", action="store_true",
                    help="show full command lines (no '...' truncation)")
    ap.add_argument("--max-cmd", type=int, default=200, metavar="N",
                    help="truncate header command lines longer than N chars "
                         "(default: 200; ignored with --full)")
    ap.add_argument("--decode", "-d", action="store_true",
                    help="base64-decode PowerShell -EncodedCommand payloads; "
                         "encoded blob becomes '<decoded: N line(s)>' in the "
                         "header and the script is printed below")

    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                    help="ANSI color output (default: auto — on when stdout is a TTY)")
    ap.add_argument("--no-color", action="store_true",
                    help="disable color (same as --color never)")

    g = ap.add_mutually_exclusive_group()
    g.add_argument("--pid", type=int, metavar="PID",
                   help="show only the subtree rooted at PID")
    g.add_argument("--tree-of", type=int, metavar="PID", dest="tree_of",
                   help="show the entire tree containing PID")
    return ap


def _resolve_palette(args):
    if args.no_color:
        return Palette(False)
    if args.color == "always":
        return Palette(True)
    if args.color == "never":
        return Palette(False)
    if os.environ.get("NO_COLOR"):
        return Palette(False)
    return Palette(sys.stdout.isatty())


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    args = build_argparser().parse_args()
    if args.max_cmd is not None and args.max_cmd < 10 and not args.full:
        sys.exit("[fatal] --max-cmd must be >= 10")

    palette = _resolve_palette(args)
    path = None if args.file in (None, "-") else args.file
    events = load_events(path)
    procs, children, roots = parse_events(events)

    total, total_roots = len(procs), len(roots)
    ancestors = []
    if args.pid is not None:
        procs, children, roots, ancestors = filter_tree(
            procs, children, roots, "pid", args.pid)
    elif args.tree_of is not None:
        procs, children, roots, _ = filter_tree(
            procs, children, roots, "tree-of", args.tree_of)

    if args.pid is not None or args.tree_of is not None:
        print(f"Parsed {total} unique processes, {total_roots} root(s) "
              f"-> filtered to {len(procs)} process(es), root: PID {roots[0]}"
              f"{_host_line(procs)}", flush=True)
        if ancestors:
            print(f"[info] note: PID {args.pid} has ancestor(s): "
                  f"{' -> '.join(ancestors)}; use --tree-of {args.pid} to "
                  f"include them", file=sys.stderr, flush=True)
        print("", flush=True)
    else:
        print(f"Parsed {total} unique processes, {total_roots} root(s)"
              f"{_host_line(procs)}\n", flush=True)

    show_host = len(_hosts_in(procs)) > 1
    max_cmd = None if args.full else args.max_cmd
    print(render(procs, children, roots,
                 max_cmd=max_cmd, decode=args.decode, palette=palette,
                 show_host=show_host),
          flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
