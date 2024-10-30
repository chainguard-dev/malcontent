rule getaddrinfo: low {
  meta:
    pledge      = "inet"
    description = "Network address and service translation"

  strings:
    $ref  = "getaddrinfo" fullword
    $ref2 = "freeaddrinfo" fullword

  condition:
    any of them
}
