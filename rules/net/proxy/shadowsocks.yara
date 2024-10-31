rule shadowsocks: high {
  meta:
    description = "shadowsocks firewall bypass tool"

  strings:
    $shadowsocks  = "shadowsocks"
    $shadowsocks2 = "Shadowsocks"

  condition:
    filesize < 100MB and any of them
}
