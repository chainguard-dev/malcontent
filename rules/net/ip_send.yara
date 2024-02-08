rule unicast {
	strings:
		$unicast = "unicast" fullword
	condition:
		any of them
}
