rule ftp {
  meta:
    description = "File Transfer Protocol (FTP)"

  strings:
    $ref  = "ftp.Dial" fullword
    $ref2 = "EPSV" fullword

  condition:
    any of them
}
