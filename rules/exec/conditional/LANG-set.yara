rule exotic_export_lang: medium {
  meta:
    description = "overrides the user-set language"

  strings:
    $export_lang = "export LANG="
    $hash_bang   = "#!"
    $not_c       = "LANG=C"
    $not_us      = "en_US.ISO-8859"

  condition:
    // The $not values are accepted locales that appear inside an "export LANG=" of their
    // own, so compare counts: an "export LANG=" beyond the accepted ones is what this rule
    // is looking for, rather than exempting the whole file.
    $export_lang and not $hash_bang in (0..2) and #export_lang > #not_c + #not_us
}
