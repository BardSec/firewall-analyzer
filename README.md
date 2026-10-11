# Firewall Analyzer

An offline desktop tool for auditing firewall configurations. Open an exported config file and it finds conflicting, shadowed, redundant, and overly permissive rules, with a what-if mode for testing rule changes before you make them on the firewall. Built with K12 network admins in mind. Nothing is sent over the network.

## Install

macOS, via Homebrew:

```bash
brew tap bardsec/tap
brew install --cask firewall-analyzer
```

macOS (DMG) and Windows (ZIP) builds are also attached to each [GitHub Release](../../releases).

## Supported Firewalls

The vendor is auto-detected from the file contents.

| Vendor | Format | Status |
|--------|--------|--------|
| Fortinet FortiGate | FortiOS text config | Supported |
| Palo Alto Networks | PAN-OS XML | Supported |
| pfSense | `config.xml` | Supported |
| Cisco ASA | | Planned (stub) |
| Cisco Meraki | | Planned (stub) |
| MikroTik RouterOS | | Planned (stub) |
| SonicWall | | Planned (stub) |

A sample FortiGate config is in `samples/` for trying the app out.

## Features

- **Overview**: summary cards, rule distribution by action, and top issues sorted by severity (Critical to Info).
- **Conflicts**: rules that match overlapping traffic but take different actions.
- **Shadowed rules**: rules that can never match because an earlier rule covers all of their traffic.
- **Redundant rules**: exact duplicates, or rules already covered by an earlier rule with the same action.
- **Permissive rules**: allow-all rules, any-address plus any-service rules, very broad ranges (/8 or larger), all-services rules, and allow rules with logging off.
- **All Rules**: the full normalized rule table.
- **What-If**: clone the rule set, edit rules, re-run the analysis, and diff the findings.
- **Export JSON**: save analysis results to a file.

## Tech Stack

- Python 3.12, PySide6 (Qt 6), PySide6-Addons for charts
- PyInstaller for packaging (`.app` on macOS, `.exe` on Windows)
- GitHub Actions for CI builds, signed and notarized releases, and Mac App Store submission

## Running from Source

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

## Building

```bash
pyinstaller build/firewall-analyzer.spec
```

CI workflows in `.github/workflows/`:

- `build.yml`: builds macOS and Windows on pushes and PRs to `main`.
- `release.yml`: on a `v*` tag, builds a signed and notarized macOS DMG and a Windows ZIP, then publishes a GitHub Release.
- `appstore.yml`: manually triggered Mac App Store build and submission.

Release signing uses these repository secrets: `APPLE_CERTIFICATE_BASE64`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_TEAM_ID`, `APPLE_ID`, `APPLE_ID_PASSWORD`. The App Store workflow also needs `APPLE_APP_CERT_BASE64`, `APPLE_APP_CERT_PASSWORD`, `APPLE_INSTALLER_CERT_BASE64`, and `APPLE_INSTALLER_CERT_PASSWORD`.

```bash
git tag v1.x.0 && git push --tags
```

## Project Structure

```
app/
  main.py            # Entry point
  models.py          # FirewallRule, Finding, and related data models
  parsers/           # One parser per vendor, plus auto-detection registry
  analysis/          # Conflict, shadowing, redundancy, and permissive detectors
  ui/
    main_window.py   # Main window and file loading
    dashboard.py     # Results view and JSON export
    panels/          # Overview, Conflicts, Shadowed, Redundant, Permissive, All Rules, What-If
    theme.py         # Dark theme
build/               # PyInstaller spec, entitlements, privacy manifest
docs/                # Privacy policy
samples/             # Example config
```
