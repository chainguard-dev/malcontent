rule crypto_aes {
	meta:
		description = "Supports AES (Advanced Encryption Standard)"
	strings:
		$ref = "crypto/aes"
		$ref2 = "AES" fullword
	condition:
		any of them
}
