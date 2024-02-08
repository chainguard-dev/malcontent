
rule gethostbyname {
	meta:
		description = "Uses libc functions to resolve network hosts"
		pledge = "???"
	strings:
		$gethostbyname2 = "gethostbyname2" fullword
		$gethostbyname = "gethostbyname" fullword
	condition:
		any of them
}
rule resolution {
	strings:
		$cannot_resolve = "cannot resolve"
	condition:
		any of them
}