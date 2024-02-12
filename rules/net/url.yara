rule url {
	meta:
		description = "Handles URL strings"
	strings:
		$ref = "NSURL"
		$ref2 = "URLContext"
	condition:
		any of them
}
