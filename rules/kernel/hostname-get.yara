
rule gethostname {
	meta:
		pledge = "sysctl"
		syscall = "sysctl"
		description = "gets the hostname of the machine"
		ref = "https://man7.org/linux/man-pages/man2/sethostname.2.html"
	strings:
		$gethostname = "gethostname"
		$proc = "/proc/sys/kernel/hostname"
		$python = "socket.gethostname"
	condition:
		any of them
}
