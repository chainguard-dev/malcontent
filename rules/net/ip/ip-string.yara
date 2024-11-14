rule inet_ntoa: medium {
  meta:
    pledge                   = "inet"
    ref                      = "https://linux.die.net/man/3/inet_ntoa"
    description              = "converts IP address from byte to string"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"

  strings:
    $ref  = "inet_ntoa" fullword
    $ref2 = "inet_ntop" fullword

  condition:
    any of them
}
