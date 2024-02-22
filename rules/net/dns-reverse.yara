rule in_addr_arpa : notable {
	meta:
		pledge = "inet"
		description = "Looks up the reverse hostname for an IP"
	strings:
		$ref = ".in-addr.arpa"
		$ref2 = "ip6.arpa"
	condition:
		any of them
}

