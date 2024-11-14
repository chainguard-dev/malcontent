rule inet_addr: medium {
  meta:
    pledge                   = "inet"
    description              = "parses IP address"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"

  strings:
    $ref = "inet_addr"

  condition:
    any of them
}

rule inet_pton: medium {
  meta:
    pledge      = "inet"
    description = "parses IP address (IPv4 or IPv6)"

  strings:
    $ref = "inet_pton"

  condition:
    any of them
}

rule ip_go: medium {
  meta:
    pledge      = "inet"
    description = "parses IP address (IPv4 or IPv6)"

  strings:
    $ref  = "IsSingleIP"
    $ref2 = "IsLinkLocalUnicast"

  condition:
    any of them
}
