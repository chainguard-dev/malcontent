rule bitsadmin: medium {
  meta:
    description = "mentions 'bitsadmin', often used for file transfers"

  strings:
    $bitsadmin = "bitsadmin" fullword

  condition:
    filesize < 250KB and all of them
}

rule bitsadmin_transfer: high {
  meta:
    description = "transfers files via 'bitsadmin'"

  strings:
    $bitsadmin = "bitsadmin"
    $transfer  = "transfer"
    $wscript   = "wscript"

  condition:
    filesize < 250KB and all of them
}

