
rule connects_and_executes : suspicious {
	meta:
		description = "Listens, provides a terminal, runs program"
	strings:
		$f_socket = "socket" fullword
		$f_execl =  "execl"  fullword
		$f_inet_addr = "inet_addr" fullword

		$not_setlocale = "setlocale" fullword
		$not_ptrace = "ptrace" fullword
		$not_usage = "Usage:"
	condition:
		all of ($f*) and none of ($not*)
}
