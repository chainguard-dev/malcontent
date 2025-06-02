rule sqlmap_override: override {
  meta:
    description                                 = "metasploit.py"
    SIGNATURE_BASE_HKTL_Sqlmap                  = "high"
    SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell = "high"

  strings:
    $c_sqlmap1 = "Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)"
    $c_sqlmap2 = "Visit 'https://github.com/sqlmapproject/sqlmap/#installation' for further details"
    $f_sqlmap3 = /SqlmapBaseException|SqlmapDataException|SqlmapFilePathException|SqlmapShellQuitException|SqlmapSilentQuitException|SqlmapUserQuitException/
    $f_sqlmap4 = "if \"sqlmap.sqlmap\" in sys.modules"

  condition:
    any of ($c*) and all of ($f*)
}
