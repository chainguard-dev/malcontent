rule iptables_append: medium linux {
  meta:
    syscall     = "posix_spawn"
    pledge      = "exec"
    description = "Appends rules to a iptables chain"

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
