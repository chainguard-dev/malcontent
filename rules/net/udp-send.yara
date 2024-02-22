rule udp_send {
	meta:
		description = "Sends UDP packets"
	strings:
		$ref = "WriteMsgUDP"
	condition:
		any of them
}

rule go_kcp : notable {
	meta:
		description = "Sends UDP packets"
	strings:
		$ref = ".ReleaseTX"
		$ref2 = ".WaitSnd"
	condition:
		all of them
}
