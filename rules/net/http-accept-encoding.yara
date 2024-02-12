rule content_type {
	meta:
		pledge = "inet"
		description = "Able to decode multiple forms of HTTP responses (example: gzip)"
	strings:
		$ref = "Accept-Encoding"
	condition:
		any of them
}
