rule mktemp {
	meta:
	  description = "Uses mktemp to create temporary files"
	strings:
		$ref = "mktemp" fullword
		$ref2 = "temp file"
		$ref3 = "ioutil/tempfile"
	condition:
		any of them
}