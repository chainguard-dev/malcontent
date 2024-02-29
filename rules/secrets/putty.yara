rule putty_ssh_sessions_reference {
  meta:
    hash_2023_ciscotools_4247 = "42473f2ab26a5a118bd99885b5de331a60a14297219bf1dc1408d1ede7d9a7a6"
  strings:
    $putty = "Software\\SimonTatham\\PuTTY\\Sessions"
  condition:
    any of them
}
