rule __progname : notable {
	meta:
		description = "get or set the programs name"
	strings:
		$ref = "__progname"
	condition:
		any of them
}