rule env_LD_PROFILE: medium {
  meta:
    description              = "may check if dynamic linker profiling is enabled"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    $val = "LD_PROFILE" fullword

  condition:
    all of them
}
