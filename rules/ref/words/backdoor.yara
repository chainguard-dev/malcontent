rule backdoor : suspicious {
	meta:
		description = "References a 'backdoor'"
	strings:
		$ref = /[a-zA-Z\-_ ]{0,16}backdoor[a-zA-Z\-_ ]{0,16}/ fullword
		$ref2 = /[a-zA-Z\-_ ]{0,16}BACKDOOR[a-zA-Z\-_ ]{0,16}/ fullword
		$ref3 = /[a-zA-Z\-_ ]{0,16}Backdoor[a-zA-Z\-_ ]{0,16}/
		$ref4 = /[a-zA-Z\-_ ]{0,16}backd00r[a-zA-Z\-_ ]{0,16}/
	condition:
		any of them
}