rule macaddr: medium {
  meta:
    description = "Retrieves network MAC address"

  strings:
    $ref  = "MAC address"
    $ref2 = "get_if_mac_addr"
    $ref3 = "macAddress" fullword

  condition:
    any of them
}

rule parse_macaddr: medium {
  meta:
    description = "Parses network MAC address"

  strings:
    $net_mac  = "net/mac.go" fullword
    $parsemac = "ParseMAC" fullword

  condition:
    any of them
}
