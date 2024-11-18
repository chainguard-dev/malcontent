rule tcp_attack: medium {
  meta:
    description = "References TCP attack"

  strings:
    $ref  = "tcp_attack" fullword
    $ref2 = "attack_tcp" fullword

  condition:
    any of them
}
