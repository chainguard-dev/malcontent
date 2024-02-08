rule crypto_aes {
	strings:
		$ref = "crypto/ecdsa"
	condition:
		any of them
}
