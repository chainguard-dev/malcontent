rule exotic_export_lang: medium {
  meta:
    description = "overrides the user-set language"

  strings:
    $export_lang = "export LANG="
    $hash_bang   = "#!"
    $not_c       = "LANG=C"
    $not_us      = "en_US.ISO-8859"

  condition:
    $export_lang and not $hash_bang in (0..2) and none of ($not*)
}
