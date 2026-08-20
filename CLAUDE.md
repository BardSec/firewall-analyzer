# Firewall Analyzer

Offline desktop tool to analyze firewall configurations. Visualizes rule conflicts,
shadowing, and overly permissive rules.

## Stack

- Python 3.12 / PySide6 (Qt 6)
- PySide6-Addons for charts
- PyInstaller 6.0+ for packaging
- Distributed via Homebrew Cask (`brew install --cask firewall-analyzer`)

## Project Layout

```
app/
  main.py            # Entry point — QApplication + MainWindow
  models.py          # Data models
  ui/
    main_window.py   # Main window layout
    theme.py         # Dark theme stylesheet
    panels/          # Analysis result tabs (conflicts, redundant, permissive, whatif, overview)
  analysis/          # Rule analysis engines
  parsers/           # Firewall config parsers (iptables, pf, etc.)
  resources/         # Icons and static assets
build/               # PyInstaller spec files
```

## Dev Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m app.main                # run from source
```

## Key Patterns

- Follows the PySide6 Desktop App archetype from global CLAUDE.md
- Panel-based UI — each analyzer gets its own QWidget tab
- Parser modules in `app/parsers/` for different firewall formats
- Analysis results rendered as tables/trees in panels
- Dark theme defined in `app/ui/theme.py`

## Build

```bash
pyinstaller build/firewall-analyzer.spec    # macOS .app bundle
```

GitHub Actions builds on push, releases on version tags.
macOS builds include code signing + notarization.
