rule tftp {
  meta:
    description = "Trivial File Transfer Protocol (TFTP)"

  strings:
    $ref  = "tftp" fullword
    $ref2 = "TFTP" fullword

  condition:
    filesize < 1MB and any of them
}
