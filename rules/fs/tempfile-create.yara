rule mktemp {
	strings:
		$ref = "mktemp" fullword
		$ref2 = "temp file"
	condition:
		any of them
}