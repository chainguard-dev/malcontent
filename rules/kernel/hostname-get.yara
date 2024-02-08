
rule gethostname {
	meta:
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$gethostname = "gethostname"
	condition:
		any of them
}
