rule sqlmap_override: override {
  meta:
    description                                 = "metasploit.py"
    SIGNATURE_BASE_HKTL_Sqlmap                  = "high"
    SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell = "high"

  strings:
    $sqlmap1 = "Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)"
    $sqlmap2 = "Visit 'https://github.com/sqlmapproject/sqlmap/#installation' for further details"
    $sqlmap3 = /SqlmapBaseException|SqlmapDataException|SqlmapFilePathException|SqlmapShellQuitException|SqlmapSilentQuitException|SqlmapUserQuitException/
    $sqlmap4 = "if \"sqlmap.sqlmap\" in sys.modules"

  condition:
    all of them
}
