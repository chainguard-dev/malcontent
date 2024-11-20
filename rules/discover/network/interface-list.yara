rule bsd_ifaddrs: medium {
  meta:
    description = "list network interfaces"

  strings:
    $getifaddrs  = "getifaddrs" fullword
    $freeifaddrs = "freeifaddrs" fullword
    $ifconfig    = "ifconfig" fullword
    $proc        = "/proc/net/dev"
    $npm         = "networkInterfaces" fullword
    $ruby        = "Socket.ip_address_list" fullword

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
    $not_busybox   = "BusyBox" fullword
    $not_snapd     = "SNAPD" fullword
    $not_rtld      = "RTLD_NEXT"

  condition:
    filesize < 10MB and all of ($get*) and all of ($LD*) and none of ($not*)
}
