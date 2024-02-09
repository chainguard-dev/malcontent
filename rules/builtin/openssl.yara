rule openssl {
	meta:
		description = "This binary includes OpenSSL source code"
	strings:
		$ref = "OpenSSL/"
	condition:
		any of them
}



