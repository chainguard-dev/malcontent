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
