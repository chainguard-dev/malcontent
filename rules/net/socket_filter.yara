rule linux_network_filter : notable {
  meta:
	description = "listens for packets without a socket"
    hash_2023_BPFDoor_dc83 = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
  strings:
    $0x = "=0x"
    $p_tcp = "tcp["
    $p_udp = "udp["
    $p_icmp = "icmp["
  condition:
    $0x and any of ($p*)
}

