rule proc_self_exe: medium {
  meta:
    description              = "gets executable associated to this process"
    pledge                   = "stdio"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"

  strings:
    $ref = "/proc/self/exe" fullword

  condition:
    any of them
}
