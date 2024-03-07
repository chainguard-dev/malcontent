rule netlink {
	meta:
		description = "communication between kernel and user space"
	strings:
		$ref = "nl_socket" fullword
		$ref2 = "AF_NETLINK" fullword
		$ref3 = "nl_connect" fullword
		$ref4 = "netlink" fullword
	condition:
		any of them
}
