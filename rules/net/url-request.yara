rule requests_urls : notable {
	meta:
		description = "requests resources via URL"
	strings:
		$ref = "NSMutableURLRequest"
		$ref2 = "import requests"
		$ref3 = "net/url"
	condition:
		any of them
}
