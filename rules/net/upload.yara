
rule upload : notable {
	meta:
		description = "Uploads files"
	strings:
		$ref = "upload" fullword
		$ref2 = "UPLOAD" fullword
		$ref3 = "Upload" fullword
	condition:
		any of them
}