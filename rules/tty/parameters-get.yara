rule tcgetattr : notable {
	meta:
		description = "get terminal parameters"
	strings:
		$ref = "tcgetaddr" fullword
		$ref2 = "cfgetospeed" fullword
	condition:
		any of them
}
