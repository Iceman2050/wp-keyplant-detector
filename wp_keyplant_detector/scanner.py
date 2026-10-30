"""Core scanner for wp-keyplant-detector.

Static, offline analysis only. PHP files are read as text and never
executed. No network access. Standard library only.
"""

import hashlib
import json
import re
from datetime import date, datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Data-driven list of known remote-management plugins (the "key plane").
# A site running one of these accepts commands signed by a remote
# management key, so a stolen key can plant plugins that look legitimate.
# ---------------------------------------------------------------------------
MANAGEMENT_PLUGINS = [
    {
        "slug_patterns": ["updraftplus", "updraftcentral", "updraft-central"],
        "name_patterns": ["updraftcentral", "updraft central", "updraftplus"],
        "product": "UpdraftCentral (via UpdraftPlus)",
    },
    {
        "slug_patterns": ["managewp", "managewp-worker", "worker"],
        "name_patterns": ["managewp"],
        "product": "ManageWP",
    },
    {
        "slug_patterns": ["mainwp", "mainwp-child"],
        "name_patterns": ["mainwp"],
        "product": "MainWP",
    },
    {
        "slug_patterns": ["infinitewp", "infinitewp-client", "iwp-client"],
        "name_patterns": ["infinitewp"],
        "product": "InfiniteWP",
    },
    {
        "slug_patterns": ["wpremote", "wp-remote", "wp-remote-manager"],
        "name_patterns": ["wp remote", "wpremote"],
        "product": "WPRemote",
    },
    {
        "slug_patterns": ["jetpack"],
        "name_patterns": ["jetpack"],
        "product": "Jetpack Manage",
    },
]

# Capabilities that let a management key change executable code on a site.
HIGH_CAPABILITY_MARKERS = (
    "install_plugins",
    "install_plugin",
    "plugin_install",
    "plugin-install",
    "install-plugin",
    "activate_plugins",
    "edit_files",
    "edit_file",
    "file_edit",
    "file-edit",
    "file_editing",
    "edit_plugins",
    "plugin_editor",
    "update_plugins",
    "delete_plugins",
    "upload_plugins",
)

# Static obfuscation / dynamic-execution patterns. PHP is matched as text.
OBFUSCATION_PATTERNS = [
    ("eval", re.compile(r"\beval\s*\(")),
    ("base64_decode", re.compile(r"\bbase64_decode\s*\(")),
    ("gzinflate", re.compile(r"\bgzinflate\s*\(")),
    ("gzuncompress", re.compile(r"\bgzuncompress\s*\(")),
    ("str_rot13", re.compile(r"\bstr_rot13\s*\(")),
    ("create_function", re.compile(r"\bcreate_function\s*\(")),
    (
        "preg_replace_e_modifier",
        re.compile(r"\bpreg_replace\s*\(\s*['\"][^'\"]*?/[a-zA-Z]*e[a-zA-Z]*['\"]"),
    ),
]

_LONG_B64 = re.compile(r"['\"]([A-Za-z0-9+/=]{200,})['\"]")
_LONG_HEX = re.compile(r"['\"]([0-9a-fA-F]{200,})['\"]")

HEADER_FIELDS = {
    "name": "Plugin Name",
    "version": "Version",
    "author": "Author",
    "author_uri": "Author URI",
    "plugin_uri": "Plugin URI",
    "description": "Description",
}


def parse_plugin_header(text):
    """Parse a WordPress plugin header comment from raw PHP text.

    Only the first 8192 characters are considered, matching WordPress's
    own header scan window. Returns a dict; missing fields are None.
    """
    head = text[:8192]
    header = {}
    for key, label in HEADER_FIELDS.items():
        m = re.search(
            r"^[ \t/*#@]*" + re.escape(label) + r"\s*:\s*(.+?)\s*$",
            head,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        header[key] = m.group(1).strip() if m else None
    return header


def hash_file(path, expected_hex):
    """Hash a file with md5 or sha256, chosen by expected hex length."""
    algo = "md5" if len(expected_hex) == 32 else "sha256"
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def discover_plugins(plugins_dir):
    """Return a list of plugin dicts found under plugins_dir.

    Supports both directory plugins (one subdir per plugin) and
    single-file plugins (a .php file directly in plugins_dir).
    Each plugin: {slug, dir (Path or None), main_file (Path or None),
    header (dict), files: [Path relative to plugin root]}.
    """
    plugins_dir = Path(plugins_dir)
    plugins = []
    for entry in sorted(plugins_dir.iterdir()):
        if entry.name.startswith("."):
            continue
        if entry.is_dir():
            php_files = sorted(entry.rglob("*.php"))
            if not php_files:
                continue
            main_file, header = _find_main_file(entry, php_files)
            plugins.append(
                {
                    "slug": entry.name,
                    "root": entry,
                    "main_file": main_file,
                    "header": header,
                    "files": php_files,
                    "all_files": sorted(
                        p for p in entry.rglob("*") if p.is_file()
                    ),
                }
            )
        elif entry.is_file() and entry.suffix.lower() == ".php":
            text = _read_text(entry)
            plugins.append(
                {
                    "slug": entry.stem,
                    "root": plugins_dir,
                    "main_file": entry,
                    "header": parse_plugin_header(text),
                    "files": [entry],
                    "all_files": [entry],
                }
            )
    return plugins


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _find_main_file(plugin_root, php_files):
    """The main file is the top-level PHP file carrying a Plugin Name header."""
    top_level = [p for p in php_files if p.parent == plugin_root]
    slug_named = plugin_root / (plugin_root.name + ".php")
    ordered = []
    if slug_named in top_level:
        ordered.append(slug_named)
    ordered.extend(p for p in top_level if p not in ordered)
    for candidate in ordered:
        header = parse_plugin_header(_read_text(candidate))
        if header.get("name"):
            return candidate, header
    # Fall back: any top-level file, then any file, with an empty-ish header.
    if ordered:
        return ordered[0], parse_plugin_header(_read_text(ordered[0]))
    first = php_files[0]
    return first, parse_plugin_header(_read_text(first))


def detect_management_plugin(plugin):
    """Return the management product name if this plugin is one, else None."""
    slug = plugin["slug"].lower()
    name = ((plugin["header"] or {}).get("name") or "").lower()
    for entry in MANAGEMENT_PLUGINS:
        if any(pat in slug for pat in entry["slug_patterns"]):
            return entry["product"]
        if name and any(pat in name for pat in entry["name_patterns"]):
            return entry["product"]
    return None


def scan_obfuscation(plugin):
    """Static obfuscation scan over every PHP file in a plugin."""
    hits = []
    root = plugin["root"]
    for php in plugin["files"]:
        text = _read_text(php)
        try:
            rel = str(php.relative_to(root)) if plugin["root"] != php.parent or True else php.name
        except ValueError:
            rel = php.name
        # For single-file plugins root is the plugins dir; relpath is fine.
        for label, pattern in OBFUSCATION_PATTERNS:
            for m in pattern.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(
                    {
                        "file": rel,
                        "pattern": label,
                        "line": line,
                        "evidence": text[m.start():m.start() + 60].splitlines()[0],
                    }
                )
        for label, pattern in (("long_base64_string", _LONG_B64),
                               ("long_hex_string", _LONG_HEX)):
            for m in pattern.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(
                    {
                        "file": rel,
                        "pattern": label,
                        "line": line,
                        "evidence": "encoded string literal of %d chars" % len(m.group(1)),
                    }
                )
    return hits


def _finding(kind, severity, plugin, evidence, file=None, key_label=None, pattern=None):
    f = {
        "kind": kind,
        "severity": severity,
        "plugin": plugin,
        "evidence": evidence,
    }
    if file is not None:
        f["file"] = file
    if key_label is not None:
        f["key_label"] = key_label
    if pattern is not None:
        f["pattern"] = pattern
    return f


def load_json_file(path, what):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize_allowlist(data):
    """Accept: [slug, ...] or {"slugs": [...]} or {slug: anything}."""
    if data is None:
        return set()
    if isinstance(data, list):
        return {str(s).lower() for s in data}
    if isinstance(data, dict):
        if "slugs" in data and isinstance(data["slugs"], list):
            return {str(s).lower() for s in data["slugs"]}
        if "allowlist" in data and isinstance(data["allowlist"], list):
            return {str(s).lower() for s in data["allowlist"]}
        return {str(k).lower() for k in data.keys()}
    raise ValueError("allowlist must be a JSON array or object")


def normalize_checksums(data):
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError("checksums file must be a JSON object keyed by plugin slug")
    return {str(k).lower(): v for k, v in data.items()}


def _parse_date(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d", "%Y/%m/%d"):
        try:
            candidate = text[:19] if "T" in fmt else text
            return datetime.strptime(candidate, fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def audit_keys(keys_data, today=None):
    """Audit a management-keys export. Returns a list of findings."""
    if not isinstance(keys_data, list):
        raise ValueError("keys file must be a JSON array of key records")
    if today is None:
        today = date.today()
    findings = []
    fingerprints = {}
    for record in keys_data:
        if not isinstance(record, dict):
            continue
        label = str(record.get("label") or record.get("name") or "(unlabeled key)")
        caps = record.get("capabilities") or record.get("caps") or []
        if isinstance(caps, str):
            caps = [caps]
        caps_norm = [str(c).strip().lower() for c in caps]
        dangerous = [c for c in caps_norm
                     if any(marker in c for marker in HIGH_CAPABILITY_MARKERS)]
        if dangerous:
            findings.append(_finding(
                "KEY-HIGH-CAPABILITY", "HIGH", None,
                "key '%s' holds code-changing capabilities: %s"
                % (label, ", ".join(sorted(set(dangerous)))),
                key_label=label,
            ))
        origin = record.get("origin")
        if origin is None or str(origin).strip() == "" or str(origin).strip().lower() == "unknown":
            findings.append(_finding(
                "KEY-UNKNOWN-ORIGIN", "MEDIUM", None,
                "key '%s' has an unknown or empty origin" % label,
                key_label=label,
            ))
        created = _parse_date(record.get("created") or record.get("created_at"))
        if created is not None:
            age = (today - created).days
            if 0 <= age <= 30:
                findings.append(_finding(
                    "KEY-RECENT", "MEDIUM", None,
                    "key '%s' was created %s (%d days before %s)"
                    % (label, created.isoformat(), age, today.isoformat()),
                    key_label=label,
                ))
        fingerprint = (record.get("fingerprint") or record.get("key_fingerprint")
                       or record.get("fingerprint_sha256") or record.get("key")
                       or record.get("key_id") or record.get("id"))
        if fingerprint:
            fingerprints.setdefault(str(fingerprint), []).append(label)
    for fingerprint, labels in fingerprints.items():
        if len(labels) > 1:
            findings.append(_finding(
                "KEY-DUPLICATE-FINGERPRINT", "HIGH", None,
                "fingerprint %s is shared by %d key records: %s"
                % (fingerprint, len(labels), ", ".join(labels)),
                key_label=", ".join(labels),
            ))
    return findings


def scan(plugins_dir, checksums=None, allowlist=None, keys_data=None, today=None):
    """Run the full scan. Returns a report dict.

    checksums: normalized map slug -> {version, files:{relpath: hex}} or None.
    allowlist: set of lowercased slugs.
    """
    allowlist = allowlist or set()
    plugins = discover_plugins(plugins_dir)
    findings = []
    plugin_reports = []

    for plugin in plugins:
        slug = plugin["slug"]
        slug_l = slug.lower()
        header = plugin["header"] or {}
        root = plugin["root"]
        not_from_wporg = False

        # --- Key-plane presence (informational) -------------------------
        product = detect_management_plugin(plugin)
        if product:
            findings.append(_finding(
                "KEY-PLANE-PRESENT", "INFO", slug,
                "remote-management plugin detected: %s (slug '%s', header name '%s'). "
                "This plugin accepts commands signed by a management key; whoever "
                "holds that key can install plugins on this site."
                % (product, slug, header.get("name") or "?"),
            ))

        # --- Provenance + integrity vs wp.org checksums ------------------
        if checksums is not None:
            entry = checksums.get(slug_l)
            if entry is None and slug_l not in allowlist:
                not_from_wporg = True
                findings.append(_finding(
                    "NOT-FROM-WP.ORG", "MEDIUM", slug,
                    "plugin slug '%s' (header name '%s') is absent from the "
                    "wp.org checksum map and absent from the allowlist"
                    % (slug, header.get("name") or "?"),
                ))
            elif entry is not None:
                expected_files = (entry or {}).get("files") or {}
                expected_norm = {str(k).replace("\\", "/"): str(v).strip().lower()
                                 for k, v in expected_files.items()}
                on_disk = {}
                for path in plugin["all_files"]:
                    try:
                        rel = str(path.relative_to(root)).replace("\\", "/")
                    except ValueError:
                        rel = path.name
                    on_disk[rel] = path
                # Single-file plugin: checksum relpaths are relative to the
                # plugins dir, on_disk rel is just the filename. That matches.
                for rel, expected_hex in sorted(expected_norm.items()):
                    if rel not in on_disk:
                        continue  # a missing file is not, by itself, a plant
                    if len(expected_hex) not in (32, 64) or not all(
                            c in "0123456789abcdef" for c in expected_hex):
                        continue
                    actual = hash_file(on_disk[rel], expected_hex)
                    if actual != expected_hex:
                        findings.append(_finding(
                            "MODIFIED-CORE-FILE", "HIGH", slug,
                            "file %s hash mismatch: on disk %s, official %s"
                            % (rel, actual, expected_hex),
                            file=rel,
                        ))
                for rel in sorted(on_disk):
                    if rel not in expected_norm:
                        findings.append(_finding(
                            "EXTRA-FILE", "MEDIUM", slug,
                            "file %s exists on disk but is absent from the "
                            "official checksum map for '%s'" % (rel, slug),
                            file=rel,
                        ))

        # --- Obfuscation scan -------------------------------------------
        hits = scan_obfuscation(plugin)
        obf_severity = "HIGH" if not_from_wporg else "MEDIUM"
        for hit in hits:
            findings.append(_finding(
                "OBFUSCATION", obf_severity, slug,
                "%s:%d matched %s: %s"
                % (hit["file"], hit["line"], hit["pattern"], hit["evidence"]),
                file=hit["file"],
                pattern=hit["pattern"],
            ))

        plugin_reports.append(
            {
                "slug": slug,
                "name": header.get("name"),
                "version": header.get("version"),
                "author": header.get("author"),
                "author_uri": header.get("author_uri"),
                "plugin_uri": header.get("plugin_uri"),
                "main_file": plugin["main_file"].name if plugin["main_file"] else None,
                "management_product": product,
                "php_files": len(plugin["files"]),
            }
        )

    if keys_data is not None:
        findings.extend(audit_keys(keys_data, today=today))

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "plugins_dir": str(plugins_dir),
        "plugins": plugin_reports,
        "findings": findings,
        "summary": {
            "plugins_scanned": len(plugin_reports),
            "findings": len(findings),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "info": counts.get("INFO", 0),
        },
    }
