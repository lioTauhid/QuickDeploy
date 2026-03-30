# quickdeploy.spec
import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, BUNDLE, COLLECT

block_cipher = None

a = Analysis(
    ['../app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('../assets', 'assets'),     # Bundle entire assets folder
        ('../ui', 'ui'),             # Bundle UI module
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
    a.binaries,
    a.zipfiles,
    a.datas,
    name='QuickDeploy',
    debug=False,
    strip=False,
    upx=True,
    console=False,          # No terminal window
    windowed=True,
    icon='../assets/logo.ico', # Windows icon
    onefile=True,           # Single executable
)

# macOS-specific .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='QuickDeploy.app',
        icon='assets/logo.icns',  # macOS requires .icns
        bundle_identifier='com.liotauhid.quickdeploy',
        info_plist={
            'NSHighResolutionCapable': True,
            'CFBundleShortVersionString': '0.9',
        },
    )
