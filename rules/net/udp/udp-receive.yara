rule udp_listen {
  meta:
    description = "Listens for UDP responses"

  strings:
    $ref  = "listenUDP"
    $ref2 = "ReadFromUDP"

  condition:
    any of them
}
