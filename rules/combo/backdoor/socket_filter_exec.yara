rule linux_network_filter_exec : suspicious {
  meta:
	description = "listens for packets without a socket, executes programs"
    hash_2023_BPFDoor_dc83 = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
  strings:
    $0x = "=0x"
    $p_tcp = "tcp["
    $p_udp = "udp["
    $p_icmp = "icmp["

    $execl = "execl" fullword
    $execve = "execve" fullword
	$e_bin_sh = "/bin/sh"
	$e_bin_bash = "/bin/bash"

	$not_cilium_node = "CILIUM_SOCK"
  condition:
    $0x and any of ($p*) and any of ($e*) and none of ($not*)
}

