rule etc_ssl_private {
	meta:
		description = "Accesses SSL private key material"
	strings:
		$ref = "/etc/ssl/private"
	condition:
		any of them
}