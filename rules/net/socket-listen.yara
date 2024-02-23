rule listen {
	meta:
		description = "listen on a socket"
		pledge = "inet"
		syscall = "accept"
	strings:
		$socket = "socket" fullword
		$listen = "listen" fullword
		$accept = "accept" fullword
		$accept64 = "accept64" fullword
	condition:
		2 of them
}


rule go_listen {
	meta:
		description = "listen on a socket"
		pledge = "inet"
		syscall = "accept"
	strings:
		$net_listen = "net.Listen"
	condition:
		any of them
}


