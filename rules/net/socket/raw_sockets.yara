
rule raw_sockets : medium {
  meta:
    description = "send raw and/or malformed IP packets"
    capability = "CAP_SYS_RAW"
    ref = "https://man7.org/linux/man-pages/man7/raw.7.html"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_b56a = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
  strings:
    $ref = "raw socket" fullword
    $hdrincl = "HDRINCL" fullword
    $sock_raw = "SOCK_RAW" fullword
    $ipproto_raw = "IPPROTO_RAW" fullword
    $proc_net_raw = "/proc/net/raw"
    $make_ip = "makeIPPacket"
    $impacket = "impacket."
  condition:
    any of them
}
