
rule iptables_delete : high {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "Deletes rules from a iptables chain"
    hash_2024_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2024_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
  strings:
    $ref = /iptables [\-\w% ]{0,8} -D[\-\w% ]{0,32}/
  condition:
    any of them
}
