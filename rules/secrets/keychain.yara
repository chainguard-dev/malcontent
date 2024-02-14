rule keychain : notable {
	meta:
		description = "Accesses the system keychain"
	strings:
		$ref = "Keychain"
		$ref2 = "keychain"
	condition:
		any of them
}
