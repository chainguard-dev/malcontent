rule udp_send {
	meta:
		description = "Sends UDP packets"
	strings:
		$ref = "WriteMsgUDP"
	condition:
		any of them
}
