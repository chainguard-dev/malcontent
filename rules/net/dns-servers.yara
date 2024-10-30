rule go_dns_refs_local {
  meta:
    description = "Examines local DNS servers"

  strings:
    $resolv         = "resolv.conf" fullword
    $dns_getservers = "dns.getServers"
    $cname          = "CNAMEResource"

  condition:
    any of them
}
