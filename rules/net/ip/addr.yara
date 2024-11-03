rule ip_addr: medium {
  meta:
    description = "mentions an 'IP address'"

  strings:
    $addr    = "IP address"
    $ipAddr  = "ipAddr"
    $ip_addr = "ip_addr"

  condition:
    filesize < 5MB and any of them
}

rule ip_addr_russion: high {
  meta:
    description = "mentions a 'IP адреса' (Russian for IP address)"

  strings:
    $addr = "IP адреса"

  condition:
    filesize < 10MB and any of them
}
