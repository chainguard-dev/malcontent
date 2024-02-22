rule progname : notable {
	meta:
		description = "get the current programs name"
	strings:
		$ref = "program_invocation_short_name"
	condition:
		any of them in (1500..3000)
}