rule gethostbyaddr {
  meta:
    description = "resolves network hosts via IP address"
    ref         = "https://linux.die.net/man/3/gethostbyaddr"
    pledge      = "dns"

  strings:
    $gethostbyname2 = "gethostbyaddr" fullword
    $ResolvHost     = "ResolvHost"
    $resolv_host    = "resolv_host"

  condition:
    any of them
}
