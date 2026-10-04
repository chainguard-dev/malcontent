rule onyx_csv_utils: override {
  meta:
    description                         = "/app/onyx/utils/csv_utils.py"
    SEKOIA_Technique_Csv_Dde_Exec_Regex = "harmless"

  strings:
    $dde_comment   = /# like `=cmd\|' \/C calc'!A1`\) against whoever opens the export\./
    $sanitize_cell = /def sanitize_csv_cell\(value: str\) -> str:/
    $prefix_chars  = /_FORMULA_PREFIX_CHARS = \("=", "\+", "-", "@", "\\t", "\\r"\)/
    $dde_any       = /=\s*(cmd|wmic|wscript|cscript|powershell)\|/ nocase

  condition:
    // the comment is the only DDE payload the file may contain
    filesize < 8KB and #dde_any == 1 and all of them
}
