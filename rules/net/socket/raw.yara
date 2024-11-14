rule raw_sockets: medium {
  meta:
    description = "send raw and/or malformed IP packets"
    capability  = "CAP_SYS_RAW"
    ref         = "https://man7.org/linux/man-pages/man7/raw.7.html"

    hash_2023_Downloads_b56a             = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"


  strings:
    $ref          = "raw socket" fullword
    $hdrincl      = "HDRINCL" fullword
    $sock_raw     = "SOCK_RAW" fullword
    $ipproto_raw  = "IPPROTO_RAW" fullword
    $proc_net_raw = "/proc/net/raw"
    $make_ip      = "makeIPPacket"
    $impacket     = "impacket."
    $makePackets  = "makePacket" fullword

  condition:
    any of them
}
