
rule kallsyms : suspicious {
	meta:
		description = "access unexported kernel symbols"
		ref = "https://lwn.net/Articles/813350/"
	strings:
		$ref = "kallsyms_lookup_name" fullword
	condition:
		any of them
}
