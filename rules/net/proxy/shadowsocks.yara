rule shadowsocks: high {
  meta:
    description = "shadowsocks firewall bypass tool"

  strings:
    $shadowsocks    = "shadowsocks"
    $shadowsocks2   = "Shadowsocks"
    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 100MB and any of ($shadow*) and none of ($not*)
}
