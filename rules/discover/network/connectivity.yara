rule network_connectivity: low {
  meta:
    description = "checks Internet connectivity"

  strings:
    $ref = "http://www.msftncsi.com/ncsi.txt"

  condition:
    any of them
}

rule bypass_gfw: medium {
  meta:
    description = "GFW bypass (Great Firewall of China)"

  strings:
    $ref = "bypass GFW"

  condition:
    any of them
}
