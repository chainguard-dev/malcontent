
rule gethostbyaddr {
	meta:
		description = "Uses libc functions to resolve network hosts"
		pledge = "???"
	strings:
		$gethostbyname2 = "gethostbyaddr" fullword
	condition:
		any of them
}