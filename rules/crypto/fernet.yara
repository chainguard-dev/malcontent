rule crypto_fernet : notable {
	meta:
		description = "Supports Fernet (symmetric encryption)"
	strings:
		$ref = "fernet" fullword
		$ref2 = "Fernet" fullword
	condition:
		any of them
}
