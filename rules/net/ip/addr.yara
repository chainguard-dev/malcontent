rule ip_addr: medium {
  meta:
    description = "mentions an 'IP address'"

  strings:
    $addr    = /IP address/
    $ipAddr  = /ipAddr/
    $ip_addr = /ip_addr/

  condition:
    filesize < 5MB and any of them
}

rule ip_addr_russion: high {
  meta:
    description = "mentions a 'IP адреса' (Russian for IP address)"

  strings:
    $addr = /IP \xD0\xB0\xD0\xB4\xD1\x80\xD0\xB5\xD1\x81\xD0\xB0/

  condition:
    filesize < 10MB and any of them
}
