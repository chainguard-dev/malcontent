rule unicast {
	meta:
		pledge = "inet"
	strings:
		$unicast = "unicast" fullword
	condition:
		any of them
}
