rule cryptonight : suspicious {
	meta:
		description = "References CryptoNight, a proof-of-work algorithm"
	strings:
		$ref = "cryptonight"
	condition:
		any of them
}



