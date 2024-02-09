rule ref {
	meta:
		description = "Able to use an HTTP proxy that requires authentication"
	strings:
		$ref = "Proxy-Authorization"
	condition:
		any of them
}
