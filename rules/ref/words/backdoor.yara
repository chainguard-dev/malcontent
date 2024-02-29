rule backdoor : suspicious {
	meta:
		description = "References a Backdoor"
	strings:
		$ref = "backdoor" fullword
		$ref2 = "BACKDOOR" fullword
		$ref3 = "Backdoor"
		$ref4 = "backd00r"
	condition:
		any of them
}