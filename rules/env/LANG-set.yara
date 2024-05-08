
rule exotic_export_lang : medium {
  meta:
    hash_2022_Gimmick_CorelDRAW = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
  strings:
    $export_lang = "export LANG="
    $hash_bang = "#!"
    $not_c = "LANG=C"
    $not_us = "en_US.ISO-8859"
  condition:
    $export_lang and not $hash_bang in (0..2) and none of ($not*)
}
