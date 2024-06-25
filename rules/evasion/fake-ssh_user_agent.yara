
rule fake_openssh_0 : high {
  meta:
    description = "Contains OpenSSH user-agent, possibly for spoofing purposes"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2020_fakessh_init = "0e6d04a2061d895d2e78c4d56a1408c22bb81f21375bfce43791afb3229ecbcd"
  strings:
    $ref = /SSH-2\.0-OpenSSH_[\w\.]{0,8}/
  condition:
    $ref
}
