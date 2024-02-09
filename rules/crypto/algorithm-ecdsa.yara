rule crypto_aes {
	meta:
		description = "Uses the Go crypto/ecdsa library"
	strings:
		$ref = "crypto/ecdsa"
	condition:
		any of them
}
