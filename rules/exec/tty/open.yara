rule openpty: medium {
  meta:
    description              = "finds and opens an available pseudoterminal"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $ref  = "openpty" fullword
    $ref2 = "pty.Open"

  condition:
    any of them
}
