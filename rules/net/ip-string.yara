
rule inet_ntoa : notable {
  meta:
    pledge = "inet"
    ref = "https://linux.die.net/man/3/inet_ntoa"
    description = "converts IP address from byte to string"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
  strings:
    $ref = "inet_ntoa" fullword
    $ref2 = "inet_ntop" fullword
  condition:
    any of them
}
