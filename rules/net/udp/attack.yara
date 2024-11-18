rule udp_attack: high {
  meta:
    description = "References UDP attack"

  strings:
    $ref  = "udp_attack" fullword
    $ref2 = "attack_udp" fullword

  condition:
    any of them
}
