
rule root_path_val : notable {
  meta:
    description = "path reference within /root"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
  strings:
    $root = /\/root\/[%\w\.\-\/]{0,64}/
    $root2 = "/root" fullword
    $not_go_selinux = "SELINUXTYPE"
  condition:
    any of them and none of ($not*)
}
