rule target_ip : suspicious {
	meta:
		description = "References a target IP"
	strings:
		$ref = "target ip"
		$ref2 = "TargetIP"
		$ref3 = "target_ip"
		$ref4 = "target IP"
	condition:
		any of them
}