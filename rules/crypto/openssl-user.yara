rule openssl_user : notable {
	meta:
		description = "Uses OpenSSL"
	strings:
		$ref = "_EXT_FLAG_SENT"
	condition:
		any of them
}
