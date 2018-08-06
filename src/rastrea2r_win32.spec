# -*- mode: python -*-


block_cipher = None

datas = [
    # required
    ("rastrea2r\\win32\\rastrea2r_win32.py",            "rastrea2r\\win32\\rastrea2r_win32.py"),
    ("rastrea2r\\*.py",         "rastrea2r\\"),
    ("rastrea2r\\*.ini",       "rastrea2r\\"),
    ("utils\\*.py",   "utils\\"),
]


a = Analysis(['rastrea2r\\win32\\rastrea2r_win32.py'],
             pathex=['C:\\Users\\sbhat5\\rastrea2r\\src\\rastrea2r\\win32'],
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
          name='rastrea2r_win32',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
