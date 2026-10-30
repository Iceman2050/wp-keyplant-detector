"""CLI: wp-keyplant-detector scan <plugins-dir> [options]."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .scanner import (
    load_json_file,
    normalize_allowlist,
    normalize_checksums,
    scan,
)


def build_parser():
    p = argparse.ArgumentParser(
        prog="wp-keyplant-detector",
        description="Audit a WordPress plugins export for backdoor plugins "
                    "planted through remote-management channels using valid "
                    "management keys (the UpdraftCentral attack class). "
                    "Offline and static: PHP is never executed and the tool "
                    "never connects to a live site.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")
    s = sub.add_parser("scan", help="scan a plugins directory export")
    s.add_argument("plugins_dir", help="wp-content/plugins-style directory to audit")
    s.add_argument("--checksums", help="JSON map slug -> {version, files:{relpath: md5/sha256}} "
                                       "for the official wp.org releases")
    s.add_argument("--keys", help="JSON array of management key records to audit")
    s.add_argument("--allowlist", help="JSON allowlist of plugin slugs known to be "
                                       "legitimate but not on wp.org")
    s.add_argument("--json", action="store_true", help="machine-readable JSON output")
    s.add_argument("--today", help="override 'today' (YYYY-MM-DD) for the recent-key "
                                   "check; defaults to the real current date")
    s.add_argument("--now", dest="today", help="alias for --today")
    return p


def _load_optional(path, what):
    if path is None:
        return None
    return load_json_file(path, what)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help(sys.stderr)
        return 2

    plugins_dir = Path(args.plugins_dir)
    if not plugins_dir.is_dir():
        print(f"error: plugins dir not found or not a directory: {args.plugins_dir}",
              file=sys.stderr)
        return 2

    today = None
    if getattr(args, "today", None):
        try:
            today = datetime.strptime(args.today, "%Y-%m-%d").date()
        except ValueError:
            print(f"error: --today must be YYYY-MM-DD, got: {args.today}", file=sys.stderr)
            return 2

    try:
        checksums_raw = _load_optional(args.checksums, "checksums")
        checksums = normalize_checksums(checksums_raw)
        allowlist_raw = _load_optional(args.allowlist, "allowlist")
        allowlist = normalize_allowlist(allowlist_raw)
        keys_data = _load_optional(args.keys, "keys")
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: malformed JSON: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        report = scan(plugins_dir, checksums=checksums, allowlist=allowlist,
                      keys_data=keys_data, today=today)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Plugins scanned: {report['summary']['plugins_scanned']}")
        for pl in report["plugins"]:
            label = pl["name"] or "(no header name)"
            print(f"  - {pl['slug']}: {label} {pl['version'] or ''}".rstrip())
        print()
        if not report["findings"]:
            print("No findings. Clean.")
        for f in report["findings"]:
            scope = f.get("plugin") or (("key:" + f["key_label"]) if f.get("key_label") else "-")
            print(f"[{f['severity']}] {f['kind']} {scope}")
            print(f"  {f['evidence']}")
        s = report["summary"]
        print()
        print(f"{s['findings']} finding(s): {s['high']} HIGH, {s['medium']} MEDIUM, "
              f"{s['info']} INFO across {s['plugins_scanned']} plugin(s)")
        if s["high"]:
            print("Verdict: FAIL - HIGH findings present. Investigate before trusting this install.")
        elif s["findings"]:
            print("Verdict: REVIEW - no HIGH findings, but items above need a human look.")
        else:
            print("Verdict: CLEAN")

    return 1 if report["summary"]["high"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
