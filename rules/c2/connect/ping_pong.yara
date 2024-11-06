rule ping_pong: medium {
  meta:
    description = "sends PING/PONG packets, possibly to a C2"

  strings:
    $ping   = "PING" fullword
    $pong   = "PONG" fullword
    $socket = "socket" fullword

  condition:
    filesize < 1MB and all of them
}

