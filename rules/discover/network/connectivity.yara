
rule network_connectivity : low {
  meta:
    description = "checks Internet connectivity"

  strings:
    $ref = "http://www.msftncsi.com/ncsi.txt"

  condition:
    any of them
}
