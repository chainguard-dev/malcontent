rule crypto_blake2b {
	meta:
		description = "Uses blake2b encryption algorithm"
	strings:
		$ref = "blake2b"
	condition:
		any of them
}
