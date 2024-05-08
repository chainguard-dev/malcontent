
rule iptables_delete : suspicious {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "Appends rules to a iptables chain"
    hash_2023_BPFDoor_8b84 = "8b84336e73c6a6d154e685d3729dfa4e08e4a3f136f0b2e7c6e5970df9145e95"
    hash_2023_BPFDoor_8b9d = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"
  strings:
    $ref = /iptables [\-\w% ]{0,8} -D[\-\w% ]{0,32}/
  condition:
    any of them
}
