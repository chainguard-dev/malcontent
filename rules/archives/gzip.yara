
rule gzip {
	meta:
		description = "Works with gzip files"
	strings:
		$ref = "gzip" fullword
	condition:
		any of them
}
