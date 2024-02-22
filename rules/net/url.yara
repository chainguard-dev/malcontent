rule url {
	meta:
		description = "Handles URL strings"
	strings:
		$ref = "NSURL"
		$ref2 = "URLContext"
		$ref3 = "RequestURI"
	condition:
		any of them
}
