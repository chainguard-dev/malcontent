
rule gethostname {
	strings:
		$gethostname = "gethostname"
		$pledge = "sysctl"
		$syscall = "sysctl"
	condition:
		any of them
}
