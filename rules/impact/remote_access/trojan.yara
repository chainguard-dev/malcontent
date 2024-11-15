rule trojan_ref: medium {
  meta:
    description = "References a Trojan"

  strings:
    $s_trojan = "trojan" fullword
    $s_Trojan = "Trojan"

  condition:
    any of ($s*)
}

rule trojan_ref_leet: high {
  meta:
    description = "References a Trojan"

  strings:
    $s_tr0jan = "tr0jan" fullword

  condition:
    any of ($s*)
}

rule trojan_ref_loaded: high {
  meta:
    description = "References a loaded Trojan"

  strings:
    $s_tr0jan = "Trojan run" fullword

  condition:
    filesize < 1MB and any of ($s*)
}
