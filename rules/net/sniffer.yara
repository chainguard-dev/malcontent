
rule pcap_user : notable {
  strings:
    $p_pcap_ = "pcap_"
    $p_PCAP_ = "PCAP_"
    $p__pcap = "_pcap"
    $p_pcapfile = "pcapfile"
    $not_dhcp = "dhcp"
    $not_pcap = "_pcap_"
    $not_dhclient = "dhclient"
    $not_tcpdump = "tcpdump"
    $not_wireshark = "wireshark"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_compdef = "#compdef"
  condition:
    any of ($p*) and none of ($not*)
}
