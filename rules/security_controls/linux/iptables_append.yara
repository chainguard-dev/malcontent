rule iptables_append: medium linux {
  meta:
    syscall                  = "posix_spawn"
    pledge                   = "exec"
    description              = "Appends rules to a iptables chain"
    hash_2023_BPFDoor_8b84   = "8b84336e73c6a6d154e685d3729dfa4e08e4a3f136f0b2e7c6e5970df9145e95"
    hash_2023_BPFDoor_8b9d   = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"
    hash_2024_Downloads_e100 = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"

  strings:
    $ref = /iptables [\-\w% ]{0,8} -A[\-\w% ]{0,32}/

  condition:
    any of them
}

rule iptables_append_broken: medium linux {
  meta:
    description = "Appends rules to a iptables chain"

  strings:
    $iptables = "iptables" fullword
    $A        = "-A"
    $INPUT    = "INPUT"

  condition:
    filesize < 5MB and all of them
}
