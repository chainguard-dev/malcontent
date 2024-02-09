rule crypto_aes {
	meta:
		description = "Uses the Go crypto/aes library"
	strings:
		$ref = "crypto/aes"
	condition:
		any of them
}
