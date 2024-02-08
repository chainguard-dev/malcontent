rule crypto_aes {
	strings:
		$ref = "crypto/aes"
	condition:
		any of them
}
