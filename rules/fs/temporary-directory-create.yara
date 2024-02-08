rule mkdtemp {
	strings:
		$ref = "mkdtemp" fullword
	condition:
		any of them
}