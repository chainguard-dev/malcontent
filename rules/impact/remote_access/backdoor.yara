private rule wordlist {
  strings:
    $scorpion = "scorpion"
    $superman = "superman"
    $porsche  = "porsche"
    $cardinal = "cardinal"
    $wombat   = "wombat"

  condition:
    filesize < 100MB and 3 of them
}

rule backdoor: medium {
  meta:
    description = "References a 'backdoor'"

  strings:
    $ref = /[a-zA-Z\-_ \']{0,16}[bB]ackdoor[a-zA-Z\-_ ]{0,16}/ fullword

    $not_vcpu    = "VCPUInfoBackdoor"
    $not_vmware  = "gGuestBackdoorOps"
    $not_comment = "# backdoor:"

  condition:
    filesize < 40MB and any of them and not wordlist and none of ($not*)
}

rule backdoor_likely: high {
  meta:
    description = "References a 'backdoor'"

  strings:
    $backdoor                     = "backdoor" fullword
    $f_ld_preload                 = "LD_PRELOAD" fullword
    $f_icmp                       = "ICMP" fullword
    $f_preload                    = "/etc/ld.so.preload"
    $f_sshd                       = "sshd" fullword
    $f_readdir64                  = "readdir64" fullword
    $not_BackdoorChannel_Fallback = "BackdoorChannel_Fallback"

  condition:
    filesize < 10MB and $backdoor and any of ($f*) and none of ($not*)
}

rule backdoor_high: high {
  meta:
    description = "references a backdoor"

  strings:
    $lower_prefix = /(hidden|hide|icmp|pam|ssh|sshd)[ _]backdoor/
    $lower_sufifx = /backdoor[_ ](task|process|up|method|user|shell|login|pass)/

  condition:
    filesize < 10MB and any of them
}

rule backdoor_caps: high {
  meta:
    description = "References a 'BACKDOOR'"

  strings:
    $ref2 = /[a-zA-Z\-_ \']{0,16}BACKDOOR[a-zA-Z\-_ ]{0,16}/ fullword

  condition:
    filesize < 40MB and any of them and not wordlist
}

rule backdoor_leet: critical {
  meta:
    description = "References a 'backd00r'"

  strings:
    $ref4 = /[a-zA-Z\-_ \']{0,16}[bB][a4]ckd00r[a-zA-Z\-_ ]{0,16}/

  condition:
    filesize < 100MB and any of them and not wordlist
}

rule commands: high {
  meta:
    description = "may accept backdoor commands"

  strings:
    $hide = "hide ok" fullword
    $show = "show ok" fullword
    $kill = "kill ok" fullword

  condition:
    all of them
}
