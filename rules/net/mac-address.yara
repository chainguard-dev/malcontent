rule macaddr {
	meta:
		description = "Retrieves network MAC address"
	strings:
		$ref = "MAC address"
		$ref2 = "get_if_mac_addr"
	condition:
		any of them
}
