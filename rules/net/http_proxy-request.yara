rule ref {
	strings:
		$ref = "Proxy-Authorization"
	condition:
		any of them
}
