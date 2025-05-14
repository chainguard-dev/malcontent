rule gethostbyaddr {
  meta:
    description = "resolves network hosts via IP address"
    ref         = "https://linux.die.net/man/3/gethostbyaddr"
    pledge      = "dns"

  strings:
    $gethostbyname2 = "gethostbyaddr" fullword
    $ResolvHost     = "ResolvHost"
    $resolv_host    = "resolv_host"
    $ruby           = "Resolv.getaddress"
    $lookup_ip      = "LookupIP"

  condition:
    any of them
}

rule resolve_base64: high {
  meta:
    description = "resolves base64-encoded address"

  strings:
    $ref = /Resolv\.getaddress\(Base64\.decode64\(.{1,64}\)\)/

  condition:
    any of them
}
