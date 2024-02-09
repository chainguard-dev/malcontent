rule content_type {
	meta:
		pledge = "inet"
		description = "Able to submit content to an HTML form"
	strings:
		$ref = "Content-Type: application/x-www-form-urlencoded"
	condition:
		any of them
}
