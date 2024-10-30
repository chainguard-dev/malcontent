rule ackflood: medium {
  meta:
    description = "References ACK flooding"

  strings:
    $ref = "ackflood" fullword

  condition:
    any of them
}
