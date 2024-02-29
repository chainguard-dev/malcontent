
rule bpf : notable {
	meta:
		capability = "CAP_SYS_BPF"
		description = "BPF (Berkeley Packet Filter)"
	strings:
		$ref = "bpf" fullword
		$ref2 = "/dev/bpf"
		$ref3 = "SetBPF" fullword
		$ref4 = "SetsockoptSockFprog"
	condition:
		any of them
}

rule linux_network_filter : suspicious {
  meta:
	description = "Linux Socket Filtering, a sneaky way to listen for traffic"
    hash_2023_BPFDoor_dc83 = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
  strings:
    $0x = "=0x"
    $p_tcp = "tcp["
    $p_udp = "udp["
    $p_icmp = "icmp["
  condition:
    $0x and any of ($p*)
}
