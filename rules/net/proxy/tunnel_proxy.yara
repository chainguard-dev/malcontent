rule tunnel_proxy: medium {
  meta:
    description = "network tunnel proxy"

  strings:
    $t_tunnel     = "tunnel" fullword
    $t_Tunnel     = "Tunnel" fullword
    $p_proxy      = "proxy" fullword
    $p_Proxy      = "Proxy" fullword
    $p_socks5     = "SOCKS5" fullword
    $s_socket     = "socket" fullword
    $c_crypto     = "crypto" fullword
    $c_tls        = "TLS13"
    $c_tlsversion = "TLSVersion"

  condition:
    any of ($t*) and any of ($p*) and any of ($s*) and any of ($c*)
}
