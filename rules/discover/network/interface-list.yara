rule bsd_ifaddrs: medium {
  meta:
    description              = "list network interfaces"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"

  strings:
    $getifaddrs  = "getifaddrs" fullword
    $freeifaddrs = "freeifaddrs" fullword
    $ifconfig    = "ifconfig" fullword
    $proc        = "/proc/net/dev"
    $npm         = "networkInterfaces" fullword

  condition:
    any of them
}

rule getifaddrs_avoid_debug: high {
  meta:
    description = "list network interfaces, avoids debugging"

  strings:
    $getifaddrs    = "getifaddrs" fullword
    $gethostbyname = "gethostbyname"
    $LD_DEBUG      = "LD_DEBUG"
    $LD_PROFILE    = "LD_PROFILE"

  condition:
    filesize < 20MB and all of them
}
