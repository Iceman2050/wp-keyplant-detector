# Acceptance Gates — wp-keyplant-detector

Written FIRST (2026-10-22), before any code. Each gate is met only when its
check command exits 0 and the expected evidence is present. A gate that
cannot be proven stays open and is reported as a handoff, never hand-waved.

Scope: offline audit of a WordPress `wp-content/plugins`-style export.
The tool reads files the owner copies/exports from their own install.
It never connects to a live site and never executes PHP.

## Gates

### G1 — Package imports and CLI help works
- Check: `python3 -m wp_keyplant_detector --help` exits 0 and mentions `scan`.
- Check: `python3 -m wp_keyplant_detector scan --help` exits 0 and lists
  `--checksums`, `--keys`, `--allowlist`, `--json`, `--today`.

### G2 — Clean plugin produces no findings, exit 0
- Fixture (a): a plugin whose files match the fixture checksum map exactly.
- Check: `python3 -m pytest tests/ -q -k clean` passes; the underlying scan
  returns zero findings and exit code 0.

### G3 — Planted plugin is caught as HIGH, exit 1
- Fixture (b): a plugin absent from checksums and allowlist, containing
  `eval(base64_decode(...))`.
- Check: pytest `-k planted` passes; scan yields a `NOT-FROM-WP.ORG`
  finding plus `OBFUSCATION` findings at severity HIGH, exit code 1.

### G4 — Tampered known plugin yields MODIFIED + EXTRA
- Fixture (c): a plugin listed in checksums where one file hash differs and
  one extra file exists on disk that is not in the checksum map.
- Check: pytest `-k tampered` passes; scan yields exactly one
  `MODIFIED-CORE-FILE` finding and one `EXTRA-FILE` finding for that plugin.

### G5 — Management plugin reported as KEY-PLANE-PRESENT (INFO)
- Fixture (d): an UpdraftCentral-style management plugin (by slug/header).
- Check: pytest `-k management` passes; scan yields a
  `KEY-PLANE-PRESENT` finding at severity INFO and exit code stays 0 when
  it is the only finding class (given a matching allowlist/checksum setup
  in the test isolates it).

### G6 — Keys export rules
- Fixture (e): one key with plugin-install/file-edit capability and an
  unknown/empty origin, plus one benign read-only key with a known origin.
- Check: pytest `-k keys` passes; the full-capability key yields a HIGH
  `KEY-HIGH-CAPABILITY` finding naming the label, plus a MEDIUM
  `KEY-UNKNOWN-ORIGIN` finding; the benign key yields no findings.

### G7 — Keys: recent and duplicate-fingerprint rules
- Check: pytest `-k "recent or duplicate"` passes; a key created within
  30 days of `--today` yields MEDIUM `KEY-RECENT`; two labels sharing one
  fingerprint yield HIGH `KEY-DUPLICATE-FINGERPRINT`.

### G8 — Hash algorithms: md5 and sha256 both supported
- Check: pytest `-k hash` passes; a checksum map using md5 (32 hex) and a
  map using sha256 (64 hex) both validate the clean fixture with no
  MODIFIED findings, and both flag a tampered file.

### G9 — Bad inputs exit 2
- Check: pytest `-k bad_input` passes; missing plugins dir, missing
  checksums file, and malformed JSON each exit 2 with an error on stderr.

### G10 — Header parsing
- Check: pytest `-k header` passes; Plugin Name, Version, Author,
  Author URI and Plugin URI are parsed from a plugin main file by static
  text parsing only (no PHP execution anywhere in the codebase).

### G11 — No network, stdlib only, no PHP execution
- Check: `grep -rn "urllib\\|requests\\|socket\\|subprocess" wp_keyplant_detector/`
  returns nothing; imports are stdlib only.

### G12 — Full test suite passes offline
- Check: `TMPDIR=~/workspace/.tmp-wp-keyplant-detector python3 -m pytest tests/ -q`
  exits 0 with all tests passed.

### G13 — Repo gate passes
- Check: `~/workspace/repo_gate.sh ~/workspace/unicorn-wave12-wp-keyplant-detector`
  exits 0 and prints `REPO GATE: PASS`.

### G14 — README completeness
- Check: README contains the dated UpdraftCentral news hook with the
  ~400,000-sites figure attributed to its source, the bring-your-own-export
  honesty note, usage, a Tests section, a "Tools used" line, all 11
  platform names linked to their live `getingeniousai.com` URLs, and the
  suite-deal link (`security-suite.html`). No personal name anywhere.
