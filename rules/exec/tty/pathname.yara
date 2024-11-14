rule ttyname: medium {
  meta:
    description              = "returns the pathname of a terminal device"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $ref = "ttyname" fullword

  condition:
    any of them
}
