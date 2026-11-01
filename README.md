# wp-keyplant-detector

**Find backdoor plugins that were planted on a WordPress site through a stolen remote-management key.** Signature scanners miss this attack class because every malicious command arrived correctly signed with a valid key. This tool audits the files on disk instead: where each plugin came from, whether its files still match the official release, whether the code hides itself, and what the site's management keys can do.

## News hook

On 18 October 2026 at 15:32 UTC, attackers began using stolen UpdraftCentral remote-management keys to install backdoor plugins on WordPress sites, according to reporting by BleepingComputer (21 October 2026) based on research from Patchstack and Nethemba. Patchstack logged at least 99 distinct backdoor plugins in the first wave, disguised as maintenance and optimization tools with names like "Site Health Cache". The commands were signed with valid private dashboard keys, so the sites treated them as genuine. Nethemba reported that its own sites were fully patched and that the attacker "came in through the UpdraftCentral remote management channel and signed the commands with valid private dashboard keys".

The exposure estimate is large. UpdraftPlus runs on more than 4 million sites, and BleepingComputer reported Patchstack's estimate that about 10% of those sites hold an UpdraftCentral or Migrator key, which puts roughly 400,000 websites in the blast radius. Updating UpdraftPlus to 1.26.13 revokes the stolen keys, but it does not remove a backdoor plugin that is already sitting in the plugins folder. That leftover plugin is what this tool hunts.

Source: [Stolen UpdraftCentral keys used to backdoor WordPress sites, BleepingComputer](https://www.bleepingcomputer.com/news/security/stolen-updraftcentral-keys-used-to-backdoor-wordpress-sites/)

## The key-plane idea, in plain words

Remote-management tools (UpdraftCentral, ManageWP, MainWP, InfiniteWP, WPRemote, Jetpack Manage) work by holding a key on your site. Whoever presents the right key can tell the site what to do: back up, update, and on many plans install plugins. That key is a second control plane next to your admin login. If the key leaks, an attacker does not need your password and does not need a bug in your code. They ask politely, with a valid signature, and the site obeys. Cleaning up after that kind of incident means two separate jobs: revoke the keys, and check every plugin file on disk, because the key revocation does nothing about code that already landed.

## How it works

This is a bring-your-own-export tool. It audits files you give it. It does not log into WordPress, it does not connect to any live site, and it never executes PHP. You copy or export your `wp-content/plugins` folder (and, if you have one, a management-keys export), then run one command:

```bash
wp-keyplant-detector scan ./plugins \
  --checksums wporg-checksums.json \
  --keys management-keys.json \
  --allowlist allowlist.json
```

What it checks:

1. **Plugin headers.** Each plugin's main PHP file is parsed as plain text for Plugin Name, Version, Author, Author URI, and Plugin URI. Directory plugins and single-file plugins are both supported.
2. **Provenance.** With `--checksums` (a JSON map of plugin slug to version and per-file hashes for the official wp.org release), any plugin that is neither in the checksum map nor in `--allowlist` is flagged `NOT-FROM-WP.ORG`. That is the shape of a planted plugin: real-looking header, no official origin.
3. **File integrity.** For plugins that are in the checksum map, a file whose hash differs from the official release is flagged `MODIFIED-CORE-FILE`, and a file on disk that the official release does not contain is flagged `EXTRA-FILE`. Both md5 (32 hex chars) and sha256 (64 hex chars) checksum maps work; the algorithm is picked from the hash length.
4. **Obfuscation.** Every PHP file is scanned as text for `eval(`, `base64_decode(`, `gzinflate(`, `gzuncompress(`, `str_rot13(`, `create_function(`, `preg_replace` with the `/e` modifier, and long encoded string literals (200+ chars). Findings name the file, line, and matched pattern. Obfuscation inside a plugin that is also `NOT-FROM-WP.ORG` is rated HIGH, because that combination is the planted-backdoor pattern.
5. **Key plane presence.** Known remote-management plugins are reported as `KEY-PLANE-PRESENT` (informational), so you know the key plane exists on the site at all.
6. **Keys export.** With `--keys` (a JSON array of records with `label`, `created`, `last_used`, `capabilities`, `origin`, and optionally `fingerprint`), the tool flags keys that can install plugins or edit files (HIGH, named by label), keys with an unknown or empty origin (MEDIUM), keys created in the last 30 days (MEDIUM; use `--today YYYY-MM-DD` to pin the reference date in tests), and the same fingerprint appearing under more than one label (HIGH).

## Verdicts

| Finding | Severity | Meaning |
|---|---|---|
| `NOT-FROM-WP.ORG` | MEDIUM | Plugin has no official wp.org origin and is not allowlisted |
| `OBFUSCATION` | MEDIUM, or HIGH when the plugin is also NOT-FROM-WP.ORG | Hidden or dynamically executed code |
| `MODIFIED-CORE-FILE` | HIGH | A file in a known plugin differs from its official release |
| `EXTRA-FILE` | MEDIUM | A file exists that the official release does not contain |
| `KEY-PLANE-PRESENT` | INFO | A remote-management plugin is installed; the key plane exists |
| `KEY-HIGH-CAPABILITY` | HIGH | A management key can install plugins or edit files |
| `KEY-UNKNOWN-ORIGIN` | MEDIUM | A management key has no recorded origin |
| `KEY-RECENT` | MEDIUM | A management key was created in the last 30 days |
| `KEY-DUPLICATE-FINGERPRINT` | HIGH | One key fingerprint appears under multiple labels |

Exit codes: `1` if any HIGH finding exists, `0` otherwise, `2` on bad inputs (missing directory, missing file, malformed JSON). Add `--json` for machine-readable output.

## Real run — the bundled fixtures

Captured 2026-11-01 against the fixture tree in `fixtures/` (a clean plugin, a
planted backdoor, a tampered wp.org plugin, and UpdraftPlus with a
full-capability management key):

```
Plugins scanned: 4

[MEDIUM] NOT-FROM-WP.ORG planted-plugin
  plugin slug 'planted-plugin' (header name 'Site Health Cache') is absent from the wp.org checksum map and absent from the allowlist
[HIGH] OBFUSCATION planted-plugin
  planted-plugin.php:11 matched eval: eval(base64_decode($payload));
[HIGH] MODIFIED-CORE-FILE tampered-plugin
  file includes/core.php hash mismatch: on disk cebd5405…, official 75c95d13…
[MEDIUM] EXTRA-FILE tampered-plugin
  file sneaky-extra.php exists on disk but is absent from the official checksum map for 'tampered-plugin'
[INFO] KEY-PLANE-PRESENT updraftplus
  remote-management plugin detected: UpdraftCentral (via UpdraftPlus) (slug 'updraftplus'). This plugin accepts commands signed by a management key; whoever holds that key can install plugins on this site.
[HIGH] KEY-HIGH-CAPABILITY key:dashboard-main
  key 'dashboard-main' holds code-changing capabilities: activate_plugins, edit_files, install_plugins

8 finding(s): 4 HIGH, 3 MEDIUM, 1 INFO across 4 plugin(s)
Verdict: FAIL - HIGH findings present. Investigate before trusting this install.
```

Reproduce it: `python -m wp_keyplant_detector scan fixtures/plugins --checksums fixtures/checksums.json --keys fixtures/keys.json --allowlist fixtures/allowlist.json` (the suite — 21 tests — passes fully offline).

## What about the live site itself?

This audit reads an export, on purpose — it never touches the running site.
For the site as attackers actually see it — exposed files, leaked keys, open
doors — run the free [BreachHunter](https://breachhunter.getingeniousai.com)
scan, and let [DomainGuard](https://domainguard.getingeniousai.com) watch the
domain around it (lookalikes, expiring certificates, DNS drift), also free.

## Input formats

Checksums (`--checksums`):

```json
{
  "clean-plugin": {
    "version": "1.2.3",
    "files": { "clean-plugin.php": "<md5-or-sha256-hex>", "includes/helper.php": "<hex>" }
  }
}
```

Allowlist (`--allowlist`): a JSON array of slugs, an object with a `slugs` array, or an object keyed by slug.

Keys (`--keys`):

```json
[
  {"label": "dashboard-main", "created": "2024-01-15", "last_used": "2026-10-20",
   "capabilities": ["install_plugins", "edit_files"], "origin": "", "fingerprint": "fp-aaaa-1111"}
]
```

## What it does NOT do

- It does not log into WordPress, call any API, or scan a live site. It reads an export you provide.
- It does not execute PHP. All checks are static text and hash comparisons.
- A `NOT-FROM-WP.ORG` result is not proof of malice on its own: premium and custom plugins are also absent from wp.org. That is what the allowlist is for. The HIGH rating is reserved for combinations that match the planted-backdoor pattern.
- It does not remove anything. It tells you what to investigate; deletion and key revocation stay in your hands.

## Install

```bash
pip install .
wp-keyplant-detector scan ./plugins --checksums wporg-checksums.json
```

Or without installing: `python -m wp_keyplant_detector scan ./plugins`.

## Tests

```bash
python -m pytest tests/ -q
```

The suite is fully offline. It builds fake plugin trees for five cases: a clean plugin whose files match its checksum map exactly (no findings, exit 0), a planted plugin with `eval(base64_decode(...))` that is absent from the checksum map (NOT-FROM-WP.ORG plus HIGH obfuscation, exit 1), a tampered wp.org plugin (one MODIFIED-CORE-FILE plus one EXTRA-FILE), a management plugin (KEY-PLANE-PRESENT info), and a keys export with one full-capability unknown-origin key and one benign read-only key (exactly the expected findings). Static versions of the same fixtures live in `fixtures/` for manual runs.

## Tools used

Built with Python 3 (standard library only: `hashlib`, `re`, `json`, `argparse`, `pathlib`), tested with pytest. No third-party runtime dependencies, no network calls.

## License

MIT. See [LICENSE](LICENSE).

---

## Built by Ingenious AI

- [DisclosureGuard](https://disclosureguard.getingeniousai.com) - AI disclosure compliance
- [ModelMinder](https://modelminder.getingeniousai.com) - model deprecation radar
- [TermsWatch](https://termswatch.getingeniousai.com) - AI vendor terms watcher
- [Vibe-Code Audit](https://vibe-audit.getingeniousai.com) - vibe-coded app security audit
- [Rogue-Agent Defense](https://rogue-defense.getingeniousai.com) - rogue agent protection
- [BreachHunter](https://breachhunter.getingeniousai.com) - breach detection
- [ChatBreaker](https://chatbreaker.getingeniousai.com) - chatbot jailbreak testing
- [Agent Flight Recorder](https://flightrecorder.getingeniousai.com) - hash-chained agent logging
- [Agent Auth Gateway](https://authgateway.getingeniousai.com) - agent budget caps and kill switch
- [DomainGuard](https://domainguard.getingeniousai.com) - domain-impersonation defense
- [ContentCraft AI](https://contentcraft.getingeniousai.com) - AI content studio

All 11 platforms in one bundle: [Ingenious AI Security Suite](https://ingeniousai-security-checks-mirror-0e97b6.gitlab.io/security-suite.html)
