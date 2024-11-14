rule rootkit_l33t: high {
  meta:
    description = "references a 'rootkit'"

  strings:
    $s_r00tkit = "r00tkit"
    $s_r00tk1t = "r00tk1t"

  condition:
    any of them
}

rule rootkit: medium {
  meta:
    description = "references a 'rootkit'"

  strings:
    $s_rootkit = "rootkit" fullword
    $s_Rootkit = "Rootkit" fullword

  condition:
    any of them
}

rule rootkit_high: high {
  meta:
    description = "references a 'rootkit'"

  strings:
    $s_rootkit     = "rootkit" fullword
    $s_Rootkit     = "Rootkit" fullword
    $not_phishing  = "phishing" fullword
    $not_keylogger = "keylogger" fullword

  condition:
    filesize < 10MB and any of ($s*) and none of ($not*)
}
