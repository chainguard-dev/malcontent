
rule tcsetattr : harmless {
	meta:
		description = "sets terminal parameters"
	strings:
		$ref = "tcsetattr" fullword
		$ref2 = "cfsetspeed" fullword
	condition:
		any of them
}
