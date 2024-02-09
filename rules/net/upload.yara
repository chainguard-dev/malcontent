
rule upload {
	meta:
		description = "Uploads files via an unknown protocol"
	strings:
		$ref = "upload" fullword
		$ref2 = "UPLOAD" fullword
	condition:
		any of them
}