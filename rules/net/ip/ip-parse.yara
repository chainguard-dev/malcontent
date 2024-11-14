rule inet_addr: medium {
  meta:
    pledge      = "inet"
    description = "parses IP address"

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
