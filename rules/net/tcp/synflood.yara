rule synflood: medium {
  meta:
    description = "References SYN flooding"

  strings:
    $ref  = "synflood" fullword
    $ref2 = "attack_SYN" fullword

  condition:
    any of them
}
