rule udp_listen {
	meta:
		description = "Listens for UDP responses"
	strings:
		$ref = "listenUDP"
	condition:
		any of them
}
