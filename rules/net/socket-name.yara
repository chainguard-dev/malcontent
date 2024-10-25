
rule getsockname : medium {
	meta:
		description = "get socket name (address)"
		ref = "https://man7.org/linux/man-pages/man2/getsockname.2.html"
	strings:
		$ref = "getsockname" fullword
	condition:
		all of them
}
