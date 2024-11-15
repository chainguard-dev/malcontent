rule socks5: medium {
  meta:
    description = "Supports SOCK5 proxies"

  strings:
    $ref              = ".Socks5"
    $ref2             = "SOCKS5"
    $rp_connect       = "CONNECT %s"
    $rp_socksproxy    = "socksproxy"
    $rp_socks_proxy   = "socks proxy"
    $rp_socksv5       = "SOCKSv5"
    $rp_socks_percent = "SOCKS %"
    $rp_socks5        = "socks5" fullword
    $rgo_socks5       = "go-socks5"
    $not_etc_services = "Registered Ports are not controlled by the IANA"

  condition:
    any of ($r*) and none of ($not*)
}

rule socks5_tunnel_server: high {
  meta:
    description = "may implement a SOCKS5 tunneling proxy server"

  strings:
    $server  = "Socks5Server"
    $server2 = "SOCKS5Serve"
    $tunnel  = "tunnel"
    $tunnel2 = "Tunnel"

  condition:
    filesize < 20MB and any of ($s*) and any of ($t*)
}
