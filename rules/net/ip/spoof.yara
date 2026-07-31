rule spoof: medium {
  meta:
    description = "references spoofing"

  strings:
    $spoof  = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
    $spoof2 = /[a-zA-Z\-_ ]{0,16}Spoof[a-zA-Z\-_ ]{0,16}/ fullword

    // same context window and fullword as $spoof2 on purpose: the netlink VF field
    // "Spoofchk" is itself a $spoof2 match, and a bare literal would report fewer
    // occurrences than $spoof2 does when the surrounding text offers several
    // start positions
    $not_chk = /[a-zA-Z\-_ ]{0,16}Spoofchk[a-zA-Z\-_ ]{0,16}/ fullword

  condition:
    // fire only on a spoof reference that "Spoofchk" does not already account for
    any of ($s*) and #spoof + #spoof2 > #not_chk
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
