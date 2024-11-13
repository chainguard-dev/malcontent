rule elf_processhide: high {
  meta:
    description                          = "userland rootkit designed to hide processes"
    hash_2023_Unix_Coinminer_Xanthe_0e6d = "0e6d37099dd89c7eed44063420bd05a2d7b0865a0f690e12457fbec68f9b67a8"
    hash_2023_Unix_Malware_Agent_7337    = "73376cbb9666d7a9528b9397d4341d0817540448f62b22b51de8f6a3fb537a3d"
    hash_2023_Unix_Trojan_Prochider_234c = "234c0dd014a958cf5958a9be058140e29f46fca99eb26f5755f5ae935af92787"

  strings:
    $prochide          = "processhide"
    $process_to_filter = "process_to_filter"

  condition:
    all of them
}

rule process_hider: high {
  meta:
    description = "possible rootkit designed to hide processes"

  strings:
    $hide_process   = "hide_proc" fullword
    $proc_hide      = "proc_hide" fullword
    $process_hide   = "process_hide" fullword
    $process_hiding = "process_hiding" fullword
    $hidden_proc    = "hidden_proc" fullword

  condition:
    filesize < 250KB and any of them
}
