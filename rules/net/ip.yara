rule packets {
	meta:
		pledge = "inet"
		description = "Internet Protocol user"
	strings:
		$invalid_packet = "invalid packet" fullword
	condition:
		any of them
}
