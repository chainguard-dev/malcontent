
rule connects_and_executes : suspicious {
	meta:
		description = "Listens, provides a terminal, runs program"
	strings:
		$socket = "socket" fullword
		$execl =  "execl"  fullword
		$inet_addr = "inet_addr" fullword
	condition:
		all of them
}
