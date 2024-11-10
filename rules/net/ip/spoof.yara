rule spoof: medium {
  meta:
    description                       = "references spoofing"
    hash_2024_enumeration_nmap        = "353fd20c9efcd0328cea494f32d3650b9346fcdb45bfe20d8dbee2dd7b62ca62"
    hash_2022_devicespoof_2_0_setup   = "15d0124f50cfee6116f6ec0704039d6fa449c5bfcbdf6e18579613457910bbe0"
    hash_2022_devicespoofer_2_2_setup = "195d69dc251a045b01fdd6854327c545283b36ebae7c54e06599b14b50ec39e6"

  strings:
    $spoof = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
    $spoof2 = /[a-zA-Z\-_ ]{0,16}Spoof[a-zA-Z\-_ ]{0,16}/ fullword

	$not_chk = "Spoofchk"
  condition:
    any of ($s*) and none of ($not*)
}
