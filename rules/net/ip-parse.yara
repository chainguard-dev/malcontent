rule inet_addr : notable {
	meta:
		pledge = "inet"
		description = "Parse an IP address"
	strings:
		$ref = "inet_addr"
	condition:
		any of them
}

rule inet_pton : notable {
	meta:
		pledge = "inet"
		description = "Parse an IP address (IPv4 or IPv6)"
	strings:
		$ref = "inet_pton"
	condition:
		any of them
}


