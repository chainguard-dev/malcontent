rule url_encode : notable {
	meta:
		description = "encodes URL, likely to pass GET variables"
	strings:
		$ref = "urlencode"
	condition:
		any of them
}
