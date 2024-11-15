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
