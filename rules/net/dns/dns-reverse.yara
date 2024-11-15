rule in_addr_arpa: medium {
  meta:
    pledge      = "inet"
    description = "looks up the reverse hostname for an IP"

  strings:
    $ref  = ".in-addr.arpa"
    $ref2 = "ip6.arpa"

  condition:
    any of them
}
