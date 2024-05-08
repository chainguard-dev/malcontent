
rule tunnel_proxy : notable {
  meta:
    description = "network tunnel proxy"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
  strings:
    $t_tunnel = "tunnel" fullword
    $t_Tunnel = "Tunnel" fullword
    $p_proxy = "proxy" fullword
    $p_Proxy = "Proxy" fullword
    $p_socks5 = "SOCKS5" fullword
    $s_socket = "socket" fullword
    $c_crypto = "crypto" fullword
    $c_tls = "TLS13"
    $c_tlsversion = "TLSVersion"
  condition:
    any of ($t*) and any of ($p*) and any of ($s*) and any of ($c*)
}
