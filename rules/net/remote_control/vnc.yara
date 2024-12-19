rule vnc_user: medium {
  meta:
    description = "uses VNC remote desktop protocol"

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
    description = "uses VNC remote desktop protocol"

  strings:
    $vnc_password = "5900"
    $vnc_         = "vnc"
    $VNC          = "VNC"

  condition:
    filesize < 5MB and uint32(0) == 1179403647 and all of them
}
