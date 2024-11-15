rule pcap_user: medium {
  meta:
    description = "uses libpcap, a packet capture library"

  strings:
    $p_pcap_       = "pcap_"
    $p_PCAP_       = "PCAP_"
    $p__pcap       = "_pcap"
    $p_pcapfile    = "pcapfile"
    $not_dhcp      = "dhcp"
    $not_pcap      = "_pcap_"
    $not_dhclient  = "dhclient"
    $not_tcpdump   = "tcpdump"
    $not_wireshark = "wireshark"
    $not_private   = "/System/Library/PrivateFrameworks/"
    $not_compdef   = "#compdef"

  condition:
    any of ($p*) and none of ($not*)
}

rule pcap_live: high {
  meta:
    description = "small opaque packet sniffer"

  strings:
    $pcap_live = "pcap_open_live"
    $not_usage = /[uU]sage:/

  condition:
    filesize < 200KB and uint32(0) == 1179403647 and $pcap_live and none of ($not*)
}
