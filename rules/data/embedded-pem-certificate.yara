rule ref {
	strings:
		$ref = "-----BEGIN CERTIFICATE-----"
	condition:
		any of them
}


