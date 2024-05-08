
rule udp_send {
  meta:
    description = "Sends UDP packets"
  strings:
    $ref = "WriteMsgUDP"
    $ref2 = "DialUDP"
  condition:
    any of them
}

rule go_kcp : notable {
  meta:
    description = "Sends UDP packets"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
  strings:
    $ref = ".ReleaseTX"
    $ref2 = ".WaitSnd"
  condition:
    all of them
}
