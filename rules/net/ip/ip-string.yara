rule inet_ntoa: medium {
  meta:
    pledge      = "inet"
    ref         = "https://linux.die.net/man/3/inet_ntoa"
    description = "converts IP address from byte to string"

  strings:
    $ref  = "inet_ntoa" fullword
    $ref2 = "inet_ntop" fullword

  condition:
    any of them
}
