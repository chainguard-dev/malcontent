rule packets {
	strings:
		$invalid_packet = "invalid packet" fullword
	condition:
		any of them
}
