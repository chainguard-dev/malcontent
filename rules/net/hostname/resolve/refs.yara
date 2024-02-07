
rule resolution {
	strings:
		$cannot_resolve = "cannot resolve"
	condition:
		any of them
}