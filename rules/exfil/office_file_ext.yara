rule office_extensions: medium {
  meta:
    description = "References multiple Office file extensions (possible exfil)"

  strings:
    $e_doc  = "doc" fullword
    $e_docm = "docm" fullword
    $e_docx = "docx" fullword
    $e_eml  = "eml" fullword
    $e_ppam = "ppam" fullword
    $e_ppt  = "ppt" fullword
    $e_pst  = "pst" fullword
    $e_xls  = "xls" fullword
    $e_xlsx = "xlsx" fullword

  condition:
    5 of them
}
