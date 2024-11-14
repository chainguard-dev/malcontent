rule exclamations: medium {
  meta:
    description            = "gets very excited"
    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"

    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

  strings:
    $exclaim = /[\w ]{2,32} [\w ]{2,32}\!{2,16}/

    $not_bug = "DYNAMIC LINKER BUG!!!"

  condition:
    $exclaim and none of ($not*)
}
