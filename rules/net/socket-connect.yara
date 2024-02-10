
rule connect {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
	strings:
		$connect = "_connect" fullword
		$connectx = "_connectx" fullword
	condition:
		any of them
}
