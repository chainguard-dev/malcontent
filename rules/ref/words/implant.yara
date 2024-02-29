rule implant : suspicious {
	meta:
		description = "References an Implant"
	strings:
		$ref = "implant" fullword
		$ref2 = "IMPLANT" fullword
		$ref3 = "Implant"
	condition:
		any of them
}