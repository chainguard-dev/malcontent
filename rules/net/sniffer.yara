rule pcap_user : notable {
  meta:
    hash_2023_Linux_Malware_Samples_1384 = "1384790107a5f200cab9593a39d1c80136762b58d22d9b3f081c91d99e5d0376"
    hash_2023_Linux_Malware_Samples_d13f = "d13fd21514f7ee5e58343aa99bf551c6a56486731c50daefcce233fdb162def8"
    hash_2023_Linux_Malware_Samples_e036 = "e0367097a1450c70177bbc97f315cbb2dcb41eb1dc052f522c9e8869e084bd0f"
    hash_2023_articles_https_www_intezer_com_blog_research_new_linux_threat_symbiote = "e7b5e412975f8106a1adaa1e2472ed902148a8ea49738b3741a13960e22c63a1"
    hash_2023_BPFDoor_dc83 = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
    hash_2023_Linux_Trojan_ShellBot_accc = "acccf2fa4e21f2cd1d7305186e4c83d6cde5ee98f1b37022b70170533e399a89"
    hash_2023_MESSAGETAP_427a = "427a0860365f15c1408708c2d6ed527e4e12ad917a1fa111d190c6601148a1eb"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
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
