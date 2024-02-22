
rule progname_socket_waitpid : suspicious {
	meta:
		description = "Sets program name, accesses internet, calls programs"
	strings:
		$dlsym = "__progname" fullword
		$openpty = "socket" fullword
		$system = "waitpid" fullword
	condition:
		all of them in (1500..3000)
}
