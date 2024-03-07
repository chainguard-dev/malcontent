
rule zip : notable {
	meta:
		description = "Works with zip files"
	strings:
		$ref = "ZIP64" fullword
		$ref2 = "archive/zip"
	condition:
		any of them
}
