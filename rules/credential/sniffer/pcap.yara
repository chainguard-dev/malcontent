rule pcap_user: medium {
  meta:
    description = "uses libpcap, a packet capture library"

  strings:
    // anchored on a non-identifier byte so an unrelated symbol that merely ends
    // in "pcap" ("usb_pcap_data", "keepcap_word", "CAP_SETPCAP") is not a hit
    $p_pcap_       = /[^\w]pcap_[a-z]/
    $p_PCAP_       = /[^\w]PCAP_[A-Z]/
    $p__pcap       = "_pcap" fullword
    $p_pcapfile    = "pcapfile"
    $not_dhcp      = "dhcp"
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
