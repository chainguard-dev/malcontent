
rule sysinfo : medium {
  meta:
    description = "get system information (load, swap)"
    syscall = "sysinfo"
    ref = "https://man7.org/linux/man-pages/man2/sysinfo.2.html"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"
  strings:
    $uname = "sysinfo" fullword
  condition:
    any of them
}
