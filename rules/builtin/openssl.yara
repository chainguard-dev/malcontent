rule openssl {
	strings:
		$ref = "OpenSSL/"
	condition:
		any of them
}



