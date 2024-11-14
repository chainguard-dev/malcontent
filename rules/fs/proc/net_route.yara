rule proc_net_route: medium {
  meta:
    description = "gets network route information"

  strings:
    $ref = "/proc/net/route"

  condition:
    any of them
}

rule proc_net_route_high: high {
  meta:
    description = "gets network route information"

  strings:
    $ref             = "/proc/net/route"
    $not_usage_route = "Usage: route"
    $not_usage_var   = "Usage: %s"
    $not_host_route  = "host route"
    $not_route_addr  = "route address"
    $not_vmtools     = "VMTools" fullword

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and $ref and none of ($not*)
}
