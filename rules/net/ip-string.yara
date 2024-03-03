rule inet_ntoa : notable {
	meta:
		pledge = "inet"
		description = "converts IP address from byte to string"
	strings:
		$ref = "inet_ntoa" fullword
		$ref2 = "inet_ntop" fullword
	condition:
		any of them
}
