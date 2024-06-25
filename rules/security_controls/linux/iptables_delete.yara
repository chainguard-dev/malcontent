rule iptables_delete : high {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "Deletes rules from a iptables chain"
  strings:
    $ref = /iptables [\-\w% ]{0,8} -D[\-\w% ]{0,32}/
  condition:
    any of them
}
