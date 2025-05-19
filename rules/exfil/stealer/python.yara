rule py_exe_stealer: critical windows {
  meta:
    description = "Compiled Python Windows Stealer"
    filetypes   = "exe,pe,py,pyc"

  strings:
    $installer      = "PyInstaller"
    $sqlite3        = "sqlite3"
    $l_cryptography = "cryptography"
    $l_requests     = "requests.__version__"
    $l_socket       = "socket"
    $l_subprocess   = "subprocess"
    $l_win32        = "win32com"
    $l_xml          = "xml.parsers.expat"
    $l_zipfile      = "zipfile"
    $l_tarfile      = "tarfile"
    $l_tempfile     = "tempfile"
    $l_ciper        = "Crypto\\Cipher"

  condition:
    filesize < 25MB and $installer and $sqlite3 and 90 % of ($l*)
}

rule py_crypto_urllib_multiprocessing: high {
  meta:
    description = "calls multiple functions useful for exfiltrating data"
    ref         = "trojan.python/drop - e8eb4f2a73181711fc5439d0dc90059f54820fe07d9727cf5f2417c5cec6da0e"

    filetypes = "py"

  strings:
    $pydata = "pydata" fullword
    $python = "python" fullword
    $import = "import "

    $f_subprocess      = "subprocess"
    $f_tarfile         = "tarfile"
    $f_urllib          = "urllib"
    $f_zipfile         = "zipfile"
    $f_blake2          = "blake2"
    $f_glob            = "glob"
    $f_multiprocessing = "multiprocessing"
    $f_libcrypto       = "libcrypto.so"
    $not_capa          = "capa.engine"
    $not_python        = "PYTHONDEBUG"
    $not_tkinter       = "tkinter" fullword
    $not_unittest      = "unittest" fullword

  condition:
    any of ($py*) and $import and 85 % of ($f*) and none of ($not*)
}
