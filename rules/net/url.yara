rule url_handle {
	meta:
		description = "Handles URL strings"
	strings:
		$ref = "NSURL"
		$ref2 = "URLContext"
		$ref3 = "RequestURI"
		$ref4 = "urllib"
	condition:
		any of them
}
