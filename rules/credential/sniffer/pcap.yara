rule pcap_user: medium {
  meta:
    hash_2023_Linux_Malware_Samples_1384 = "1384790107a5f200cab9593a39d1c80136762b58d22d9b3f081c91d99e5d0376"
    hash_2023_Linux_Malware_Samples_d13f = "d13fd21514f7ee5e58343aa99bf551c6a56486731c50daefcce233fdb162def8"
    hash_2023_Linux_Malware_Samples_e036 = "e0367097a1450c70177bbc97f315cbb2dcb41eb1dc052f522c9e8869e084bd0f"

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
