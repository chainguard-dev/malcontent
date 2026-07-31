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
    $ref                   = "/proc/net/route"
    $not_vmtools           = "VMTools" fullword
    $notgrp_route_usage    = "Usage: route"
    $notgrp_route_usagevar = "Usage: %s"
    $notgrp_route_host     = "host route"
    $notgrp_route_addr     = "route address"

  condition:
    // The four $notgrp_route strings together are the net-tools "route" usage
    // banner; alone they are worthless ("Usage: %s" appears in almost any ELF),
    // so they only suppress as a complete set.
    filesize < 1MB and uint32(0) == 1179403647 and $ref and none of ($not_*) and not all of ($notgrp_route*)
}
