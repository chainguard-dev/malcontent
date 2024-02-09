
rule zip : suspicious {
	meta:
		description = "Works with zip files"
	strings:
		$ref = "ZIP64" fullword
	condition:
		any of them
}
