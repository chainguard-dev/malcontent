
rule powershell : notable {
  meta:
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Linux_Malware_Samples_5f80 = "5f80945354ea8e28fa8191a37d37235ce5c5448bffb336e8db5b01719a69128f"
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"
  strings:
    $val = /powershell[ \w\-]{0,32}/ fullword
    $not_completions = "powershell_completion"
  condition:
    $val and none of ($not*)
}
