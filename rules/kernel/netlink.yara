rule netlink {
  meta:
    description = "communicate with kernel services"

  strings:
    $ref  = "nl_socket" fullword
    $ref2 = "AF_NETLINK" fullword
    $ref3 = "nl_connect" fullword
    $ref4 = "netlink" fullword

  condition:
    any of them
}
