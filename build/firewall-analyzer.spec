# PyInstaller spec file for Firewall Analyzer
# Build with: pyinstaller build/firewall-analyzer.spec

import sys

block_cipher = None

a = Analysis(
    ['../app/main.py'],
    pathex=['..'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PySide6.QtCharts',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest'],
    noarchive=False,
    optimize=0,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Firewall Analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Firewall Analyzer',
)

if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='Firewall Analyzer.app',
        icon='build/icon.icns' if sys.platform == 'darwin' else None,
        bundle_identifier='com.bardsec.firewall-analyzer',
        info_plist={
            'CFBundleName': 'Firewall Analyzer',
            'CFBundleDisplayName': 'Firewall Analyzer',
            'CFBundleShortVersionString': '1.0.0',
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '12.0',
            'NSHumanReadableCopyright': 'Copyright \u00a9 2026 BardSec',
            'LSApplicationCategoryType': 'public.app-category.developer-tools',
        },
    )
