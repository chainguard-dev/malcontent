rule root_path_val: medium {
  meta:
    description = "path reference within /root"

    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

  strings:
    $root           = /\/root\/[%\w\.\-\/]{0,64}/
    $root2          = "/root" fullword
    $not_go_selinux = "SELINUXTYPE"

  condition:
    any of them and none of ($not*)
}
