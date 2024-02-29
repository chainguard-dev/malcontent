rule backdoor : suspicious {
	meta:
		description = "References a Backdoor"
	strings:
		$ref = "backdoor" fullword
		$ref2 = "BACKDOOR" fullword
		$ref3 = "Backdoor"
	condition:
		any of them
}