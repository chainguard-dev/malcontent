rule upnp_client: medium {
  meta:
    description = "UPnP network client"

  strings:
    $upnp_firewall   = "WANIPv6FirewallControl"
    $upnp_schema     = "schemas-upnp-org"
    $u_ssdp_discover = "ssdp:discover"
    $u_addr          = "239.255.255.250"
    $not_igd         = "UPnP/IGD"
    $not_c1          = "CaptureOne"

  condition:
    any of ($u*) and none of ($not*)
}
