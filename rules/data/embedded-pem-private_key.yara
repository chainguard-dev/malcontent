rule ref {
	strings:
		$ref = "PRIVATE KEY-----"
	condition:
		any of them
}


