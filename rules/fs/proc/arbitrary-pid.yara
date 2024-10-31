
rule proc_arbitrary : medium {
  meta:
    description = "access /proc for arbitrary pids"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2023_Downloads_98e7 = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
  strings:
    $string_val = /\/proc\/[%{$][\/\$\w\}]{0,12}/
  condition:
    any of them
}


rule pid_match : medium {
  meta:
    description = "scan /proc for matching pids"
  strings:
    $string_val = /\/proc\/\\d[\/\$\w\}]{0,12}/
  condition:
    any of them
}
