
rule office_extensions : medium {
  meta:
    description = "References multiple Office file extensions (possible exfil)"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
    hash_2023_Downloads_f5de = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
  strings:
    $e_doc = "doc" fullword
    $e_docm = "docm" fullword
    $e_docx = "docx" fullword
    $e_eml = "eml" fullword
    $e_ppam = "ppam" fullword
    $e_ppt = "ppt" fullword
    $e_pst = "pst" fullword
    $e_xls = "xls" fullword
    $e_xlsx = "xlsx" fullword
  condition:
    5 of them
}
