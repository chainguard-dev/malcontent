
rule multicast {
	meta:
		description = "send data to multiple nodes simultaneously"
	strings:
		$multicast = "multicast" fullword
	condition:
		any of them
}