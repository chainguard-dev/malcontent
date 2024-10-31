
rule udp_send {
  meta:
    description = "Sends UDP packets"
  strings:
    $ref = "WriteMsgUDP"
    $ref2 = "DialUDP"
  condition:
    any of them
}

rule go_kcp : medium {
  meta:
    description = "Sends UDP packets"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
    hash_2024_downloaded_8c69 = "8c692dcc964bac87e6a566d3122bc63021af3460541a4d54f41338c147999330"
  strings:
    $ref = ".ReleaseTX"
    $ref2 = ".WaitSnd"
  condition:
    all of them
}
