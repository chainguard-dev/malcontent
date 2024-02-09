
rule gethostname {
	meta:
		pledge = "sysctl"
		syscall = "sysctl"
		description = "gets the hostname of the machine"
	strings:
		$gethostname = "gethostname"
	condition:
		any of them
}
