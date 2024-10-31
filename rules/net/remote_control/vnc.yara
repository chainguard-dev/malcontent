rule vnc_user: medium {
  meta:
    hash_2023_Linux_Malware_Samples_1d28 = "1d2800352e15175ae5fa916b48a96b26f0199d9f8a9036648b3e44aa60ed2897"
    hash_2023_Linux_Malware_Samples_5a62 = "5a628dc26dae0309941d70021cfbb4281189f85b074bf3e696058d73c4609101"
    hash_2023_Linux_Malware_Samples_d13f = "d13fd21514f7ee5e58343aa99bf551c6a56486731c50daefcce233fdb162def8"

  strings:
    $vnc_password = "vnc_password"
    $vnc_         = "VNC_"
    $vnc_port     = ":5900"
    $not_synergy  = "SYNERGY"

  condition:
    any of ($vnc*) and none of ($not*)
}

rule vnc_elf_subtle: medium {
  meta:
    hash_2023_Linux_Malware_Samples_1d28 = "1d2800352e15175ae5fa916b48a96b26f0199d9f8a9036648b3e44aa60ed2897"
    hash_2023_Linux_Malware_Samples_5a62 = "5a628dc26dae0309941d70021cfbb4281189f85b074bf3e696058d73c4609101"
    hash_2023_Linux_Malware_Samples_d13f = "d13fd21514f7ee5e58343aa99bf551c6a56486731c50daefcce233fdb162def8"

  strings:
    $vnc_password = "5900"
    $vnc_         = "vnc"
    $VNC          = "VNC"

  condition:
    filesize < 3MB and uint32(0) == 1179403647 and all of them
}
