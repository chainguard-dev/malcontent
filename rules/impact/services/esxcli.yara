rule esxcli_caller: high linux {
  meta:
    description = "invokes 'esxcli'"

  strings:
    $esxcli = "esxcli"

  condition:
    any of them
}

rule esxcli_onion_ransom: critical linux {
  meta:
    description = "ransomware targeting VMware ESXi"

  strings:
    $esxcli = "esxcli"
    $onion  = ".onion"

    $w_cyber     = "cyber"
    $w_victim    = "victim"
    $w_encrypted = "encrypted"
    $w_tor       = "tor" fullword
    $w_Tor       = "Tor" fullword
    $w_TOR       = "TOR" fullword
    $w_company   = "company" fullword
    $w_your      = "your data"
    $w_incident  = "incident"

  condition:
    $esxcli and $onion and any of ($w*)
}
