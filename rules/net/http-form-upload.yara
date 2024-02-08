rule content_type {
	strings:
		$ref = "Content-Type: application/x-www-form-urlencoded"
	condition:
		any of them
}
