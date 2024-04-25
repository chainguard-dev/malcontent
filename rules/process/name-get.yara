rule progname : notable {
	meta:
		description = "get the current process name"
		ref = "https://linux.die.net/man/3/program_invocation_short_name"
	strings:
		$ref = "program_invocation_short_name"
	condition:
		any of them in (1200..3000)
}