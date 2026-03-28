# quickdeploy.spec
import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, BUNDLE, COLLECT

block_cipher = None

a = Analysis(
    ['app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('assets', 'assets'),
        ('ui', 'ui'),
    ],
    hiddenimports=['PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],                         # ← Empty list, NOT a.binaries/a.datas
    exclude_binaries=True,      # ← Binaries handled by COLLECT instead
    name='QuickDeploy',
    debug=False,
    strip=False,
    upx=True,
    console=False,
    windowed=True,
    icon='assets/logo.ico',
    # onefile=True  ← REMOVED
)

# COLLECT replaces onefile bundling on all platforms
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='QuickDeploy',
)

# macOS-specific .app bundle — now receives COLLECT, not EXE
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,                   # ← Pass coll, not exe
        name='QuickDeploy.app',
        icon='assets/logo.icns',
        bundle_identifier='com.liotauhid.quickdeploy',
        info_plist={
            'NSHighResolutionCapable': True,
            'CFBundleShortVersionString': '0.9',
        },
    )