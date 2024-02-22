rule inet_ntoa : notable {
	meta:
		pledge = "inet"
		description = "Convert IP from byte form to string"
	strings:
		$ref = "inet_ntoa" fullword
	condition:
		any of them
}
