
rule system : notable {
	meta:
		description = "execute a shell command"
		syscalls = "fork,execl"
		ref = "https://man7.org/linux/man-pages/man3/system.3.html"
	strings:
		$system = "system" fullword
	condition:
		all of them in (1200..3000)
}
