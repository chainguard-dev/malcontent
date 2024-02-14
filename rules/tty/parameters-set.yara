
rule tcgetattr : notable {
	meta:
		description = "gets terminal parameters"
	strings:
		$ref = "tcgetaddr" fullword
		$ref2 = "cfgetospeed" fullword
	condition:
		any of them
}
