
rule fake_openssh_0 : high {
  meta:
    description = "Contains OpenSSH user-agent, possibly for spoofing purposes"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
  strings:
    $ref = /SSH-2\.0-OpenSSH_[\w\.]{0,8}/
  condition:
    $ref
}
