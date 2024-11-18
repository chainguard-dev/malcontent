rule spoof: medium {
  meta:
    description = "references spoofing"

  strings:
    $spoof  = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
    $spoof2 = /[a-zA-Z\-_ ]{0,16}Spoof[a-zA-Z\-_ ]{0,16}/ fullword

    $not_chk = "Spoofchk"

  condition:
    any of ($s*) and none of ($not*)
}

rule spoof_attack: high {
  meta:
    description = "references spoof attack"

  strings:
    $spoof  = /[a-zA-Z\-_ ]{0,16}spoofAttack[a-zA-Z\-_ ]{0,16}/ fullword
    $spoof2 = /[a-zA-Z\-_ ]{0,16}SpoofAttack[a-zA-Z\-_ ]{0,16}/ fullword

  condition:
    any of ($s*)
}
