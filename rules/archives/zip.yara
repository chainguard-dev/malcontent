
rule zip : notable {
	meta:
		description = "Works with zip files"
	strings:
		$ref = "ZIP64" fullword
	condition:
		any of them
}
