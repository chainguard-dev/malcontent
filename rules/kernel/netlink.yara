

rule netlink : suspicious {
	meta:
		description = "communication between kernel and user space (possible network sniffer)"
	strings:
		$ref = "nl_socket" fullword
		$ref2 = "AF_NETLINK" fullword
		$ref3 = "nl_connect" fullword
		$ref4 = "netlink" fullword
	condition:
		any of them
}
