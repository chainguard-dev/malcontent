rule spoof : medium {
	meta:
		description = "references spoofing"
	strings:
		$ref = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
		$ref2 = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
	condition:
		any of them
}