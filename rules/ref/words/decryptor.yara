rule decryptor : notable {
	meta:
		description = "References 'decryptor'"
	strings:
		$ref = "decryptor"
	condition:
		any of them
}