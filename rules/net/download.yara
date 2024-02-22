
rule download : notable {
	meta:
		description = "Downloads files"
	strings:
		$ref = "download" fullword
		$ref2 = "DOWNLOAD" fullword
		$ref3 = "Download" fullword
	condition:
		any of them
}