rule ref {
	strings:
		$ref = "HTTP/2" fullword
	condition:
		any of them
}
