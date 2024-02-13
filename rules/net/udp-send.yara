rule udp_listen {
	meta:
		description = "Sends UDP packets"
	strings:
		$ref = "WriteMsgUDP"
	condition:
		any of them
}
