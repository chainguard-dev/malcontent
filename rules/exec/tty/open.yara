rule openpty: medium {
  meta:
    description = "finds and opens an available pseudoterminal"

  strings:
    $ref  = "openpty" fullword
    $ref2 = "pty.Open"

  condition:
    any of them
}
