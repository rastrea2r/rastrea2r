# -*- mode: python -*-


block_cipher = None

datas = [
    # required
    ("rastrea2r\\windows\\rastrea2r_windows.py",            "rastrea2r\\windows\\rastrea2r_windows.py"),
    ("rastrea2r\\*.py",         "rastrea2r\\"),
    ("rastrea2r\\*.ini",       "rastrea2r\\"),
    ("utils\\*.py",   "utils\\"),
]


a = Analysis(['rastrea2r\\windows\\rastrea2r_windows.py'],
             pathex=['C:\\Code\rastrea2r\\src\\rastrea2r\\windows',
             'C:\\Program Files (x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x86',
             'C:\\Program Files (x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x64'],
             binaries=[],
             datas=datas,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='rastrea2r',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
