rule tunnel: medium {
  meta:
    description              = "creates a network tunnel"
    syscall                  = "setsockopt"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $tunnel = "tunnel" fullword
    $inet   = "inet_addr" fullword

  condition:
    all of them
}

rule tunnel2: medium {
  meta:
    description = "creates a network tunnel"
    syscall     = "setsockopt"

  strings:
    $Tunnel = "Tunnel"
    $inet   = "inet_addr" fullword

  condition:
    all of them
}
