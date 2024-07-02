rule synflood : medium {
  meta:
    description = "References SYN flooding"
  strings:
    $ref = "synflood" fullword
  condition:
    any of them
}
