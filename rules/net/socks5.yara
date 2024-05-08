
rule socks5 : notable {
  meta:
    description = "Supports SOCK5 proxies"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
  strings:
    $ref = ".Socks5"
    $ref2 = "SOCKS5"
    $rp_connect = "CONNECT %s"
    $rp_socksproxy = "socksproxy"
    $rp_socks_proxy = "socks proxy"
    $rp_socksv5 = "SOCKSv5"
    $rp_socks_percent = "SOCKS %"
    $rp_socks5 = "socks5" fullword
    $rgo_socks5 = "go-socks5"
    $not_etc_services = "Registered Ports are not controlled by the IANA"
  condition:
    any of ($r*) and none of ($not*)
}
