rule requests_urls : notable {
	meta:
		description = "Makes network requests using a URL"
	strings:
		$ref = "NSMutableURLRequest"
	condition:
		any of them
}
