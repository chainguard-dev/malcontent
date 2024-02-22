
rule _connect {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
	strings:
		$connect = "_connect" fullword
		$connectx = "_connectx" fullword
	condition:
		any of them
}



rule connect {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
	strings:
		$connect = "connect" fullword
	condition:
		any of them in (1500..3000)
}
