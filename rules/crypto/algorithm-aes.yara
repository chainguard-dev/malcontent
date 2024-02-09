rule crypto_aes {
	meta:
		description = "Uses the Go crypto/aes library"
	strings:
		$ref = "crypto/aes"
		$ref2 = "AES" fullword
	condition:
		any of them
}
