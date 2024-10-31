rule upnp_client: medium {
  meta:
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2023_Linux_Malware_Samples_1fce = "1fce1d5b977c38e491fe84e529a3eb5730d099a4966c753b551209f4a24524f3"
    hash_2023_Linux_Malware_Samples_206a = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"

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
