# -*- mode: python ; coding: utf-8 -*-
import fido2
import os

_fido2_dir = os.path.dirname(fido2.__file__)

a = Analysis(
    ['hsm_guir.py'],
    pathex=[],
    binaries=[],
    datas=[
        (os.path.join(_fido2_dir, 'public_suffix_list.dat'), 'fido2'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PicoHSMManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
