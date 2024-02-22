rule __progname : suspicious {
	meta:
		description = "get or more typically set the current programs name"
	strings:
		$ref = "__progname"
	condition:
		any of them
}