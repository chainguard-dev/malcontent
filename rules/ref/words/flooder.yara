

rule flooder : suspicious {
	meta:
		description = "References an IP flooder"
	strings:
		$ref = "flooder" fullword
		$ref2 = "FLOODER" fullword
		$ref3 = "Flood operation"
	condition:
		any of them
}