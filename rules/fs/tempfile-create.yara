rule mktemp {
	meta:
	  description = "Uses mktemp to create temporary files"
	strings:
		$ref = "mktemp" fullword
		$ref2 = "temp file"
	condition:
		any of them
}