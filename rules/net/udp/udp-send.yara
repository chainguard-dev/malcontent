rule udp_send {
  meta:
    description = "Sends UDP packets"

  strings:
    $ref  = "WriteMsgUDP"
    $ref2 = "DialUDP"

  condition:
    any of them
}

rule go_kcp: medium {
  meta:
    description = "Sends UDP packets"

  strings:
    $ref  = ".ReleaseTX"
    $ref2 = ".WaitSnd"

  condition:
    all of them
}
