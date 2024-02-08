
rule multicast {
	strings:
		$multicast = "multicast" fullword
	condition:
		any of them
}