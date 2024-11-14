rule powershell: medium {
  meta:
    hash_2023_Linux_Malware_Samples_5f80 = "5f80945354ea8e28fa8191a37d37235ce5c5448bffb336e8db5b01719a69128f"
    hash_2020_IPStorm_IPStorm_unpacked   = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"

  strings:
    $val             = /powershell[ \w\-]{0,32}/ fullword
    $not_completions = "powershell_completion"

  condition:
    $val and none of ($not*)
}
