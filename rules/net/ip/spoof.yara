rule spoof: medium {
  meta:
    description                     = "references spoofing"
    hash_2024_enumeration_nmap      = "353fd20c9efcd0328cea494f32d3650b9346fcdb45bfe20d8dbee2dd7b62ca62"


  strings:
    $spoof  = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
    $spoof2 = /[a-zA-Z\-_ ]{0,16}Spoof[a-zA-Z\-_ ]{0,16}/ fullword

    $not_chk = "Spoofchk"

  condition:
    any of ($s*) and none of ($not*)
}
