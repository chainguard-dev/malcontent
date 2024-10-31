
rule iptables_delete : medium {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "Deletes rules from a iptables chain"
    hash_2024_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
  strings:
    $ref = /iptables [\-\w% ]{0,8} -D[\-\w% ]{0,32}/
  condition:
    any of them
}
