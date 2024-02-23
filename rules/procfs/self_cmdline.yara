
rule proc_self_cmdline : notable {
	meta:
		description = "Gets the command-line associated to this process"
		pledge = "stdio"
	strings:
		$ref = "/proc/self/cmdline" fullword
	condition:
		any of them
}
