
rule uname {
	meta:
		description = "get system identification"
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$uname = "uname" fullword
	condition:
		any of them
}
