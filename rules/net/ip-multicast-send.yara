
rule multicast {
	meta:
		description = "Send data to multiple nodes simultaneously"
	strings:
		$multicast = "multicast" fullword
	condition:
		any of them
}