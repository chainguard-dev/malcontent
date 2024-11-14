rule powershell: medium {
  meta:
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"

  strings:
    $val             = /powershell[ \w\-]{0,32}/ fullword
    $not_completions = "powershell_completion"

  condition:
    $val and none of ($not*)
}
