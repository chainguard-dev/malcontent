rule decryptor : notable {
	meta:
		description = "References 'dropper'"
	strings:
		$ref = "dropper" fullword
		$ref2 = "Dropper" fullword
	condition:
		any of them
}