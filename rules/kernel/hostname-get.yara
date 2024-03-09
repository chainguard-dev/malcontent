
rule gethostname {
	meta:
		pledge = "sysctl"
		syscall = "sysctl"
		description = "gets the hostname of the machine"
	strings:
		$gethostname = "gethostname"
		$proc = "/proc/sys/kernel/hostname"
		$python = "socket.gethostname"
	condition:
		any of them
}
