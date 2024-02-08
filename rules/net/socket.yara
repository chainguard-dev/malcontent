rule sendmsg {
	meta:
		description = "send a message to a socket"
		syscall = "sendmsg"
	strings:
		$sendmsg = "sendmsg" fullword
	condition:
		any of them
}

rule recvmsg {
	meta:
		description = "receive a message from a socket"
		syscall = "sendmsg"
	strings:
		$sendmsg = "recvmsg" fullword
	condition:
		any of them
}



rule setsockopt {
	meta:
		description = "set socket options"
		syscall = "setsockopt"
	strings:
		$setsockopt = "setsockopt" fullword
	condition:
		any of them
}